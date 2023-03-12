using Microsoft.Windows.EventTracing;
using Microsoft.Windows.EventTracing.Symbols;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Threading.Tasks;

namespace TraceAnalyzer
{
    [Cmdlet("Analyze", "HeapSnapshot")]
    public class AnalyzeHeapSnapshot : TraceAnalyzerBase
    {
        [Parameter()]
        public string FilePath { get; set; }

        [Parameter()]
        public long ProcessId { get; set; }

        [Parameter()]
        public int MaxStackIdCount { get; set; } = 100;

        public AnalyzeHeapSnapshot()
        {
            this.ProfileName = "HeapSnapshot";
        }

        protected override void ProcessRecord()
        {
            try
            {
                using (ITraceProcessor trace = TraceProcessor.Create(this.FilePath))
                {
                    var pendingSnapshotData = trace.UseHeapSnapshots();
                    var pendingSymbols = trace.UseSymbols();

                    Log("start processing trace");
                    trace.Process();
                    Log("end processing trace");
                    var snapshotData = pendingSnapshotData.Result;
                    pendingSymbols.Result.LoadSymbolsForConsoleAsync(SymCachePath.Automatic, SymbolPath.Automatic).GetAwaiter().GetResult();
                    Log("end loading symbols");

                    var allSnapshotHandleMap = new Dictionary<long, List<SnapshotInfo>>();
                    var allStackTextsHanleMap = new Dictionary<long, Dictionary<string, StackInfo>>();

                    Log("Total snapshots: {0}", snapshotData.Snapshots.Count);
                    ulong totalAllocations = 0;
                    foreach (var snapshot in snapshotData.Snapshots.Reverse())
                    {
                        if (snapshot.Process.Id != this.ProcessId)
                        {
                            Log("skip process: {0}, {1}", snapshot.Process.ImageName, snapshot.Process.Id);
                            continue;
                        }

                        var timestamp = snapshot.Timestamp.DateTimeOffset.LocalDateTime;

                        var snapshotHandleMap = new Dictionary<long, SnapshotInfo>();

                        foreach (var allocation in snapshot.Allocations)
                        {
                            totalAllocations++;
                            var stackId = string.Format("{0:X}", allocation.SnapshotUniqueStackId.Value);
                            var stackText = allocation.Stack.GetDebuggerString();
                            var bytes = allocation.Size.Bytes;
                            var handle = allocation.HeapHandle;

                            if (!snapshotHandleMap.ContainsKey(handle))
                            {
                                snapshotHandleMap.Add(handle, new SnapshotInfo() {
                                        Handle = handle,
                                        Timestamp = timestamp
                                });
                            }

                            if (!snapshotHandleMap[handle].Stacks.ContainsKey(stackId))
                            {
                                var stackByte = new StackByteCount()
                                {
                                    StackId = stackId,
                                    Bytes = bytes,
                                    Count = 1

                                };
                                snapshotHandleMap[handle].Stacks.Add(stackId, stackByte);
                            }
                            else
                            {
                                snapshotHandleMap[handle].Stacks[stackId].Bytes += bytes;
                                snapshotHandleMap[handle].Stacks[stackId].Count++;
                            }

                            snapshotHandleMap[handle].TotalBytes += bytes;

                            if (!allStackTextsHanleMap.ContainsKey(handle))
                            {
                                allStackTextsHanleMap.Add(handle, new Dictionary<string,StackInfo>());
                            }

                            if (!allStackTextsHanleMap[handle].ContainsKey(stackId))
                            {
                                var stackInfo = new StackInfo(){
                                    StackId = stackId,
                                    StackText = stackText,
                                    AllocationMaxBytes = bytes,
                                    AllocationMinBytes = bytes,
                                };
                                allStackTextsHanleMap[handle].Add(stackId, stackInfo);
                            }
                            else
                            {
                                var maxBytes = System.Math.Max(allStackTextsHanleMap[handle][stackId].AllocationMaxBytes, bytes);
                                allStackTextsHanleMap[handle][stackId].AllocationMaxBytes = maxBytes;

                                var minBytes = System.Math.Min(allStackTextsHanleMap[handle][stackId].AllocationMinBytes, bytes);
                                allStackTextsHanleMap[handle][stackId].AllocationMinBytes = minBytes;
                            }
                        }

                        // Merge into total map
                        foreach(var pair in snapshotHandleMap)
                        {
                            var handle = pair.Key;
                            var info = pair.Value;
                            if (!allSnapshotHandleMap.ContainsKey(handle))
                            {
                                allSnapshotHandleMap.Add(handle, new List<SnapshotInfo>());
                            }

                            allSnapshotHandleMap[handle].Add(info);
                        }

                        foreach(var pair in allSnapshotHandleMap)
                        {
                            Log("Handle: {0}, snapshots: {1}", pair.Key, pair.Value.Count);
                        }
                    }

                    Log("TotalAllocation: {0}", totalAllocations);

                    var handleResults = new List<PSObject>();
                    foreach (var pair in allSnapshotHandleMap)
                    {
                        var handle = pair.Key;
                        var allSnapshots = pair.Value;
                        var result = this.Analyze(allSnapshots, allStackTextsHanleMap[handle], this.MaxStackIdCount);
                        if (result != null)
                        {
                            handleResults.Add(result);
                        }
                    }
                    WriteObject(handleResults);
                }
            }
            catch (Exception e)
            {
                Log(e.Message);
                Log(e.StackTrace);
            }
        }
    }

}
