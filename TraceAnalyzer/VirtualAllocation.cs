using Microsoft.Windows.EventTracing;
using Microsoft.Windows.EventTracing.Events;
using Microsoft.Windows.EventTracing.Processes;
using Microsoft.Windows.EventTracing.Symbols;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TraceAnalyzer
{
    [Cmdlet("Analyze", "VirtualAllocation")]
    public class AnalyzeVirtualAllocation : TraceAnalyzerBase
    {
        [Parameter(Position = 1)]
        public string FilePath { get; set; }

        [Parameter()]
        public long ProcessId { get; set; }

        [Parameter()]
        public List<DateTime> Timestamps { get; set; }

        [Parameter()]
        public int MaxStackIdCount { get; set; } = 100;

        public AnalyzeVirtualAllocation()
        {
            this.ProfileName = "VirtualAllocation";
        }


        protected override void ProcessRecord()
        {
            try
            {
                this.Timestamps = this.Timestamps.OrderByDescending(x => x).ToList();
                Log("FilePath: {0}", this.FilePath);
                Log("ProcessId: {0}", this.ProcessId);
                Log("SnapshotTimestamps:");
                foreach(var timestamp in this.Timestamps)
                {
                    Log("{0}", timestamp);
                }

                using (ITraceProcessor trace = TraceProcessor.Create(this.FilePath))
                {
                    var allAllocations = new List<AllocationInfo>();

                    TraceEventCallback handleKernelMemoryEvent = (EventContext eventContext) =>
                    {
                        ClassicEvent classicEvent = eventContext.Event.AsClassicEvent;
                        int eventId = classicEvent.Id;

                        const int virtualAllocEventId = 98;
                        const int virtualFreeEventId = 99;

                        if (classicEvent.ProcessId != this.ProcessId || classicEvent.Version < 2 || (eventId != virtualAllocEventId && eventId != virtualFreeEventId))
                        {
                            return;
                        }
                        allAllocations.Add(GetAllocationInfo(ref classicEvent));
                    };

                    Guid kernelMemoryProviderId = new Guid("3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c");

                    var pendingStackDataSource = trace.UseStacks();
                    trace.Use(new Guid[] { kernelMemoryProviderId }, handleKernelMemoryEvent);
                    var pendingSymbols = trace.UseSymbols();

                    Log("start processing");
                    trace.Process();
                    Log("end processing");

                    pendingSymbols.Result.LoadSymbolsForConsoleAsync(SymCachePath.Automatic, SymbolPath.Automatic).GetAwaiter().GetResult();

                    Log("Total virtual allocations: {0}", allAllocations.Count);

                    var unknownCommittedRanges = new Dictionary<DateTime, AddressRanges>();
                    var heapCommittedRanges = new Dictionary<DateTime, AddressRanges>();
                    var allocationMap = new Dictionary<DateTime, Dictionary<ulong, AllocationInfo>>();
                    var reserveMap = new Dictionary<ulong, AllocationInfo>();

                    foreach(var datetime in this.Timestamps)
                    {
                        unknownCommittedRanges[datetime] = new AddressRanges(this.Log);
                        heapCommittedRanges[datetime] = new AddressRanges(this.Log);
                        allocationMap[datetime] = new Dictionary<ulong, AllocationInfo>();
                    }

                    ulong counter = 0;

                    foreach(var alloc in allAllocations.OrderBy(x=>x.Timestamp))
                    {
                        counter++;
                        if (counter % 100000 == 0)
                        {
                            Log("Merging allocations completed {0:F4} %", (counter * 100.0 / (ulong)allAllocations.Count));
                        }
                        var stackData = pendingStackDataSource.Result.GetStack(alloc.Timestamp, alloc.ThreadId);
                        bool isReserve =  alloc.Flags.HasFlag(VirtualAllocFlags.Reserve);
                        bool isCommitted =  alloc.Flags.HasFlag(VirtualAllocFlags.Commit);
                        bool isDecommitted = alloc.Flags.HasFlag(VirtualAllocFlags.Decommit);
                        bool isRelease =  alloc.Flags.HasFlag(VirtualAllocFlags.Release);
                        var timestamp = alloc.Timestamp.DateTimeOffset.LocalDateTime;


                        if (isReserve)
                        {
                            reserveMap[alloc.Base] = alloc;
                        }

                        var bytes = (ulong)alloc.Bytes;

                        if (isRelease)
                        {
                            // MEM_RELEASE require the bytes to be zero, so get the real bytes.
                            if (reserveMap.ContainsKey(alloc.Base))
                            {
                                bytes = (ulong)reserveMap[alloc.Base].Bytes;
                                reserveMap.Remove(alloc.Base);
                            }
                        }

                        var range = new AddrRange(){
                            Timestamp = alloc.Timestamp,
                            ThreadId = alloc.ThreadId,
                            Start = alloc.Base,
                            End = alloc.Base + bytes
                        };


                        foreach(var snapshotTime in this.Timestamps.Where(x => timestamp <= x))
                        {

                            if (isCommitted)
                            {
                                if (stackData == null)
                                {
                                    unknownCommittedRanges[snapshotTime].AddRange(range);
                                }
                                else if (!stackData.GetDebuggerStringList().Any(x => x == "ntdll!RtlpAllocateHeapInternal" || x == "ntdll!RtlCreateHeap"))
                                {
                                    //KernelBase!VirtualAlloc  App VirtualAllocation
                                    allocationMap[snapshotTime][alloc.Base] = alloc;
                                }
                                else
                                {
                                    //ntdll!RtlpAllocateHeapInternal and ntdll!RtlCreateHeap  heap VirtualAllocation
                                    heapCommittedRanges[snapshotTime].AddRange(range);
                                }
                            }

                            if (isRelease || isDecommitted)
                            {
                                unknownCommittedRanges[snapshotTime].RemoveRange(range);
                                if (allocationMap[snapshotTime].ContainsKey(alloc.Base))
                                {
                                    allocationMap[snapshotTime].Remove(alloc.Base);
                                }
                                else
                                {
                                    heapCommittedRanges[snapshotTime].RemoveRange(range);
                                }
                            }
                        }
                    }


                    Log("Start aggregating stacks");
                    var allStackTexts = new Dictionary<string,StackInfo>();
                    var allSnapshots = new List<SnapshotInfo>();
                    foreach(var datetime in this.Timestamps)
                    {
                        var snapshot = new SnapshotInfo();

                        snapshot.Timestamp = datetime;

                        var stacks = new Dictionary<string, StackByteCount>();
                        long stackTotalBytes = 0;
                        foreach(var allocation in allocationMap[datetime].Values)
                        {
                            var stackData = pendingStackDataSource.Result.GetStack(allocation.Timestamp, allocation.ThreadId);
                            if (stackData == null)
                            {
                                continue;
                            }

                            var stackText = string.Join("\r\n", stackData.GetDebuggerStringList().Reverse());
                            string stackId = string.Format("{0:X}",stackText.GetHashCode());

                            long bytes = allocation.Bytes;

                            stackTotalBytes += bytes;

                            if (!stacks.ContainsKey(stackId))
                            {
                                var stack = new StackByteCount(){
                                    StackId = stackId,
                                    Bytes = bytes,
                                    Count = 1

                                };

                                stacks.Add(stackId, stack);
                            }
                            else
                            {
                                stacks[stackId].Bytes += bytes;
                                stacks[stackId].Count++;
                            }

                            if (!allStackTexts.ContainsKey(stackId))
                            {
                                var stackInfo = new StackInfo(){
                                    StackId = stackId,
                                    StackText = stackText,
                                    AllocationMaxBytes = bytes,
                                    AllocationMinBytes = bytes,
                                };
                                allStackTexts.Add(stackId, stackInfo);
                            }
                            else
                            {
                                var maxBytes = System.Math.Max(allStackTexts[stackId].AllocationMaxBytes, bytes);
                                allStackTexts[stackId].AllocationMaxBytes = maxBytes;

                                var minBytes = System.Math.Min(allStackTexts[stackId].AllocationMinBytes, bytes);
                                allStackTexts[stackId].AllocationMinBytes = minBytes;
                            }
                        }

                        Log("{0}: RangeCount: {1}",datetime, heapCommittedRanges[datetime].Ranges.Count);

                        snapshot.Stacks = stacks;
                        snapshot.UnknownCommitted = unknownCommittedRanges[datetime].TotalBytes;
                        snapshot.HeapCommitted = heapCommittedRanges[datetime].TotalBytes;
                        snapshot.TotalBytes = stackTotalBytes + snapshot.HeapCommitted + snapshot.UnknownCommitted;
                        allSnapshots.Add(snapshot);
                    }

                    Log("start analyzing");
                    var result = this.Analyze(allSnapshots, allStackTexts, this.MaxStackIdCount);
                    if (result != null)
                    {
                        WriteObject(result);
                    }
                }
            }
            catch (Exception e)
            {
                Log(e.Message);
                Log(e.StackTrace);
            }
        }


        private AllocationInfo GetAllocationInfo(ref ClassicEvent classicEvent)
        {
            VirtualAlloc64EventData eventData;

            if (classicEvent.Is32Bit)
            {
                if (classicEvent.Data.Length != Marshal.SizeOf<VirtualAlloc32EventData>())
                {
                    throw new InvalidTraceDataException("Invalid virtual alloc/free event.");
                }

                VirtualAlloc32EventData thunk = MemoryMarshal.Read<VirtualAlloc32EventData>(classicEvent.Data);

                eventData.Base = thunk.Base;
                eventData.Size = thunk.Size;
                eventData.ProcessId = thunk.ProcessId;
                eventData.Flags = thunk.Flags;
            }
            else
            {
                if (classicEvent.Data.Length != Marshal.SizeOf<VirtualAlloc64EventData>())
                {
                    throw new InvalidTraceDataException("Invalid virtual alloc/free event.");
                }

                eventData = MemoryMarshal.Read<VirtualAlloc64EventData>(classicEvent.Data);
            }

            var info = new AllocationInfo()
            {
                Timestamp = classicEvent.Timestamp,
                ThreadId = (int)classicEvent.ThreadId,
                Base = eventData.Base,
                Bytes = (long)eventData.Size,
                Flags = eventData.Flags
            };

            return info;
        }
    }

    struct VirtualAlloc64EventData
    {
        public ulong Base;
        public ulong Size;
        public uint ProcessId;
        public VirtualAllocFlags Flags;
    }

    struct VirtualAlloc32EventData
    {
#pragma warning disable CS0649
        public uint Base;
        public uint Size;
        public uint ProcessId;
        public VirtualAllocFlags Flags;
#pragma warning restore CS0649
    }

    [Flags]
    enum VirtualAllocFlags : uint
    {
        None = 0,
        Commit = 0x1000,
        Reserve = 0x2000,
        Decommit = 0x4000,
        Release = 0x8000,
        Reset = 0x80000,
        TopDown = 0x100000,
        WriteWatch = 0x200000,
        Physical = 0x400000,
        ResetUndo = 0x1000000,
        LargePages = 0x20000000
    }

    class AllocationInfo
    {
        public TraceTimestamp Timestamp;
        public int ThreadId;
        public ulong Base;
        public long Bytes;
        public VirtualAllocFlags Flags;
    }

}
