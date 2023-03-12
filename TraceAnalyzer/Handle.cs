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
    [Cmdlet("Analyze", "Handles")]
    public class AnalyzeHandles : TraceAnalyzerBase
    {
        [Parameter()]
        public string FilePath { get; set; }

        [Parameter()]
        public long ProcessId { get; set; }

        public AnalyzeHandles()
        {
            this.ProfileName = "Handle";
        }

        protected override void ProcessRecord()
        {
            try
            {
                using (ITraceProcessor trace = TraceProcessor.Create(this.FilePath))
                {
                    var pendingHandleData = trace.UseHandles();
                    var pendingSymbolDataSource = trace.UseSymbols();

                    Log("start processing");
                    trace.Process();
                    Log("end processing");

                    pendingSymbolDataSource.Result.LoadSymbolsForConsoleAsync(SymCachePath.Automatic, SymbolPath.Automatic).GetAwaiter().GetResult();
                    Log("end loading symbols");

                    var handles = new List<PSObject>();

                    Log("totalHandles: {0}", pendingHandleData.Result.OtherHandles.Count);

                    foreach (var handleData in pendingHandleData.Result.OtherHandles)
                    {
                        if(handleData.CreatingProcess == null || handleData.CreatingProcess.Id != this.ProcessId || (handleData.CreatingStack != null && handleData.ClosingStack != null))
                        {
                            continue;
                        }

                        string createStack = "";
                        string closeStack = "";
                        if (handleData.CreatingStack != null)
                        {
                             createStack = handleData.CreatingStack.GetDebuggerString();
                        }

                        if (handleData.ClosingStack != null)
                        {
                            closeStack = handleData.ClosingStack.GetDebuggerString();
                        }

                        var handleInfo = new PSObject();

                        handleInfo.Properties.Add(new PSNoteProperty("CreateStack", createStack));
                        handleInfo.Properties.Add(new PSNoteProperty("CloseStack", closeStack));
                        handles.Add(handleInfo);
                    }

                    var result = new PSObject();
                    result.Properties.Add(new PSNoteProperty("Handles", handles));

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
