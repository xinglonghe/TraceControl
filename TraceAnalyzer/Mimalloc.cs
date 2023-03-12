using Microsoft.Windows.EventTracing;
using Microsoft.Windows.EventTracing.Events;
using Microsoft.Windows.EventTracing.Symbols;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Management.Automation.Tracing;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;



namespace TraceAnalyzer
{
    [Cmdlet("Analyze", "Mimalloc")]
    public class AnalyzeMimalloc : TraceAnalyzerBase
    {
        [Parameter(Position = 1)]
        public string FilePath { get; set; }

        [Parameter()]
        public long ProcessId { get; set; }

        [Parameter()]
        public List<DateTime> Timestamps { get; set; }

        [Parameter()]
        public SwitchParameter IsDebug { get; set; }

        public AnalyzeMimalloc()
        {
            this.ProfileName = "Mimalloc";
        }


        protected override void ProcessRecord()
        {
            try
            {
                if (this.Timestamps != null)
                {
                    if (this.Timestamps.Count != 2)
                    {
                        Log("Need 2 timestamps");
                        return;
                    }

                    Log("StartTime: {0}, EndTime: {1}", this.Timestamps[0], this.Timestamps[1]);
                }

                var trace = TraceProcessor.Create(this.FilePath);
                {
                    var allocs = new Dictionary<ulong, EventData>();
                    var frees = new Dictionary<ulong, EventData>();
                    var unexpectedEvents = new List<EventData>();
                    List<EventData> allEvents = new List<EventData>();

                    TraceEventCallback handleEvents = (EventContext eventContext) =>
                    {
                        if (eventContext.Event.ProcessId != this.ProcessId)
                        {
                            return;
                        }

                        var eventId = eventContext.Event.Id;

                        // 100 is alloc, 101 is free
                        if (eventId == 100 || eventId == 101)
                        {
                            var timeStamp = eventContext.Event.Timestamp;
                            var threadId = eventContext.Event.ThreadId;
                            var payload = MemoryMarshal.Read<EventPayload>(eventContext.Event.Data);

                            if (this.IsDebug)
                            {
                                allEvents.Add(new EventData
                                {
                                    EventId = eventId,
                                    Timestamp = timeStamp,
                                    ThreadId = (int)threadId,
                                    Base = payload.Base,
                                    Size = payload.Size
                                });
                            }

                            if (this.Timestamps != null && (timeStamp.DateTimeOffset.LocalDateTime < this.Timestamps[0] || timeStamp.DateTimeOffset.LocalDateTime > this.Timestamps[1]))
                            {
                                return;
                            }


                            if (eventId == 101)
                            {
                                if (allocs.ContainsKey(payload.Base))
                                {
                                    if (payload.Size != allocs[payload.Base].Size)
                                    {
                                        unexpectedEvents.Add(new EventData
                                        {
                                            EventId = eventId,
                                            Timestamp = timeStamp,
                                            ThreadId = (int)threadId,
                                            Base = payload.Base,
                                            Size = payload.Size,
                                            Tag = "UnMatchSize"
                                        });
                                    }
                                    else
                                    {
                                        allocs.Remove(payload.Base);
                                    }
                                }
                                else
                                {
                                    if (frees.ContainsKey(payload.Base))
                                    {
                                        unexpectedEvents.Add(
                                        new EventData()
                                        {
                                            EventId = eventId,
                                            Timestamp = timeStamp,
                                            ThreadId = (int)threadId,
                                            Base = payload.Base,
                                            Size = payload.Size,
                                            Tag = "UnMatchBase"
                                        });
                                    }
                                    else
                                    {
                                        frees.Add(payload.Base,
                                            new EventData()
                                            {
                                                EventId = eventId,
                                                Timestamp = timeStamp,
                                                ThreadId = (int)threadId,
                                                Base = payload.Base,
                                                Size = payload.Size
                                            });
                                    }
                                }
                            }
                            else
                            {
                                if (allocs.ContainsKey(payload.Base))
                                {
                                    unexpectedEvents.Add(
                                        new EventData()
                                        {
                                            EventId = eventId,
                                            Timestamp = timeStamp,
                                            ThreadId = (int)threadId,
                                            Base = payload.Base,
                                            Size = payload.Size,
                                            Tag = "UnFree"
                                        });
                                }
                                else
                                {
                                    allocs.Add(payload.Base,
                                        new EventData()
                                        {
                                            EventId = eventId,
                                            Timestamp = timeStamp,
                                            ThreadId = (int)threadId,
                                            Base = payload.Base,
                                            Size = payload.Size
                                        });
                                }
                            }
                        }
                        else
                        {
                            Log("unexpected event {0}", eventId);
                        }
                    };

                    Guid providerId = new Guid("138f4dbb-ee04-4899-aa0a-572ad4475779");
                    var pendingStackDataSource = trace.UseStacks();
                    trace.Use(new Guid[] { providerId }, handleEvents);
                    var pendingSymbols = trace.UseSymbols();

                    Log("start processing");
                    trace.Process();
                    Log("end processing");

                    pendingSymbols.Result.LoadSymbolsForConsoleAsync(SymCachePath.Automatic, SymbolPath.Automatic).GetAwaiter().GetResult();
                    Log("end loading symbols");

                    Log("got allocs:{0}, frees: {1}", allocs.Count, frees.Count);

                    var result = new PSObject();

                    var noStackEvents = new List<EventData>();

                    Log("Aggregate stacks for Allocs");
                    result.Properties.Add(new PSNoteProperty("Allocs", GetStacks(allocs.Values.ToList(), pendingStackDataSource.Result, noStackEvents)));
                    Log("Aggregate stacks for Frees");
                    result.Properties.Add(new PSNoteProperty("Frees", GetStacks(frees.Values.ToList(), pendingStackDataSource.Result, noStackEvents)));
                    result.Properties.Add(new PSNoteProperty("unexpectedEvents", GetEventObjs(unexpectedEvents, pendingStackDataSource.Result)));
                    if (this.IsDebug)
                    {
                        result.Properties.Add(new PSNoteProperty("NoStackEvents", GetEventObjs(noStackEvents, pendingStackDataSource.Result)));
                        allEvents = allEvents.Where(x=> unexpectedEvents.Any(y=>y.Base == x.Base) || noStackEvents.Any(z=>z.Base == x.Base)).ToList();
                        result.Properties.Add(new PSNoteProperty("UnknowEvents", GetEventObjs(allEvents, pendingStackDataSource.Result)));
                    }

                    this.WriteObject(result);
                }
            }
            catch (Exception e)
            {
                Log(e.Message);
                Log(e.StackTrace);
            }
        }

        private List<PSObject> GetEventObjs(List<EventData> events, IStackDataSource stackSource)
        {
            var eventObjs = new List<PSObject>();
            foreach(var e in events)
            {
                var obj = new PSObject();
                var stackData = stackSource.GetStack(e.Timestamp, e.ThreadId);
                if (stackData != null)
                {
                    var stackText = stackData.GetDebuggerString();
                    obj.Properties.Add(new PSNoteProperty("StackText", stackText));
                }
                else
                {
                    obj.Properties.Add(new PSNoteProperty("StackText", "Unknown"));
                    e.Tag = "NoStack";
                }
                obj.Properties.Add(new PSNoteProperty("EventId", e.EventId));
                obj.Properties.Add(new PSNoteProperty("ThreadId", e.ThreadId));
                obj.Properties.Add(new PSNoteProperty("Timestamp", e.Timestamp.DateTimeOffset.LocalDateTime));
                obj.Properties.Add(new PSNoteProperty("Base", e.Base));
                obj.Properties.Add(new PSNoteProperty("Size", e.Size));
                obj.Properties.Add(new PSNoteProperty("Tag", e.Tag));
                eventObjs.Add(obj);
            }

            return eventObjs;
        }

        private List<PSObject> GetStacks(List<EventData> events, IStackDataSource stackSource, List<EventData> noStackEvents)
        {
            var stacks = new Dictionary<string, StackBytes>();
            foreach(var e in events)
            {
                string stackText = "";
                var stackData = stackSource.GetStack(e.Timestamp, (int)e.ThreadId);
                if (stackData == null)
                {
                    stackText = "Unknown";
                    if (this.IsDebug)
                    {
                        noStackEvents.Add(e);
                    }
                }
                else
                {
                    stackText = stackData.GetDebuggerString();
                }

                if (stacks.ContainsKey(stackText))
                {
                    stacks[stackText].Size += e.Size;
                    stacks[stackText].Count++;
                }
                else
                {
                    stacks[stackText] = new StackBytes()
                    {
                        Size = e.Size,
                        Count = 1,
                    };
                }
            }

            var objs = stacks.OrderByDescending(x => x.Value.Size).Take(100).Select(x =>
            {
                var obj = new PSObject();
                obj.Properties.Add(new PSNoteProperty("Size", x.Value.Size));
                obj.Properties.Add(new PSNoteProperty("Count", x.Value.Count));
                obj.Properties.Add(new PSNoteProperty("StackText", x.Key));
                return obj;
            }).ToList();

            return objs;
        }
    }

    public class EventData
    {
        public int EventId;
        public int ThreadId;
        public TraceTimestamp Timestamp;
        public ulong Base;
        public ulong Size;
        public string Tag;
    }
    public struct EventPayload
    {
        public ulong Base;
        public ulong Size;
    }

    public class StackBytes {
        public ulong Size;
        public ulong Count;
    }
}
