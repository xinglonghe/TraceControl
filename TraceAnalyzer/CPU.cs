using Microsoft.Windows.EventTracing;
using Microsoft.Windows.EventTracing.Events;
using Microsoft.Windows.EventTracing.Processes;
using Microsoft.Windows.EventTracing.Symbols;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TraceAnalyzer
{
    [Cmdlet("Analyze", "CPUSamples")]
    public class AnalyzeCPUSamples : TraceAnalyzerBase
    {
        [Parameter()]
        public string FilePath { get; set; }

        [Parameter()]
        public long ProcessId { get; set; }

        public AnalyzeCPUSamples()
        {
            this.ProfileName = "CPU";
        }

        protected override void ProcessRecord()
        {
            try
            {
                using (ITraceProcessor trace = TraceProcessor.Create(this.FilePath))
                {
                    var pendingCpuSampleData = trace.UseCpuSamplingData();
                    var pendingSymbolDataSource = trace.UseSymbols();

                    Log("start processing");
                    trace.Process();
                    Log("end processing");

                    pendingSymbolDataSource.Result.LoadSymbolsForConsoleAsync(SymCachePath.Automatic, SymbolPath.Automatic).GetAwaiter().GetResult();
                    Log("end loading symbols");

                    var stackSamples = new Dictionary<string, Decimal>();

                    ulong totalCount = 0;

                    foreach (var sampleData in pendingCpuSampleData.Result.Samples)
                    {
                        totalCount++;
                        if(sampleData.Process.Id != this.ProcessId)
                        {
                            continue;
                        }

                        var stackData = sampleData.Stack;
                        if (stackData == null)
                        {
                            continue;
                        }

                        var stackText = stackData.GetDebuggerString();
                        if (string.IsNullOrEmpty(stackText))
                        {
                            continue;
                        }

                        if (!stackSamples.ContainsKey(stackText))
                        {
                            stackSamples.Add(stackText, sampleData.Weight.TotalMilliseconds);                       }
                        else
                        {
                            stackSamples[stackText] += sampleData.Weight.TotalMilliseconds;
                        }
                    }

                    Log("Total stackSamples {0}", totalCount);
                    Log("Uniq stacks for process {0}: {1}", this.ProcessId, stackSamples.Count);

                    var stackObjs = stackSamples.OrderByDescending(x=>x.Value).Take(100).Select(x =>
                    {
                        var obj = new PSObject();
                        obj.Properties.Add(new PSNoteProperty("StackText", x.Key));
                        obj.Properties.Add(new PSNoteProperty("TotalMs", x.Value));
                        return obj;
                    }).ToList();

                    var result = new PSObject();
                    result.Properties.Add(new PSNoteProperty("Stacks", stackObjs));

                    WriteObject(result);
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
