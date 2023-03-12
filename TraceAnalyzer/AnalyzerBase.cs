using Microsoft.Windows.EventTracing;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Threading.Tasks;

namespace TraceAnalyzer
{
    public class TraceAnalyzerBase : Cmdlet
    {
        protected void Log(string formatStr, params object[] args)
        {
            string prefix = string.Format("[{0}][ {1} ][{2}] ", DateTime.Now.ToString("MM/dd/yyyy hh:mm:ss"), Environment.MachineName, this.ProfileName);
            string content = string.Format(formatStr, args);
            WriteInformation(prefix + content, null);
        }

        public  string ProfileName { get; set; }

        protected PSObject Analyze(List<SnapshotInfo> allSnapshots, Dictionary<string, StackInfo> allStackTexts, int maxStackCount)
        {
            var allStackIds = allStackTexts.Keys.ToList();
            Log("AllStackIds: {0}", allStackIds.Count);

            foreach (var stackId in allStackIds)
            {
                foreach (var info in allSnapshots)
                {
                    if (!info.Stacks.ContainsKey(stackId))
                    {
                        info.Stacks.Add(stackId, new StackByteCount
                        {
                            StackId = stackId,
                            Bytes = 0
                        });
                    }
                }
            }

            var firstInfo = allSnapshots.First();
            var lastInfo = allSnapshots.Last();
            var totalDiffByStackId = new Dictionary<string, long>();
            foreach (var stackId in allStackIds)
            {
                totalDiffByStackId.Add(stackId, firstInfo.Stacks[stackId].Bytes - lastInfo.Stacks[stackId].Bytes);
            }

            var stackIdsHasDiff = totalDiffByStackId.Where(x => x.Value != 0).OrderByDescending(x => x.Value).Select(x => x.Key).ToList();

            List<string> activityStackIds = null;

            if (stackIdsHasDiff.Count <= maxStackCount)
            {
                activityStackIds = stackIdsHasDiff.Take(maxStackCount).ToList();

            }
            else
            {
                activityStackIds = stackIdsHasDiff.Take(maxStackCount / 2).ToList();
                activityStackIds.AddRange(stackIdsHasDiff.TakeLast(maxStackCount / 2).ToList());
            }

            Log("StackIdsHasDiff: {0}", stackIdsHasDiff.Count);
            Log("activityStackIds: {0}", activityStackIds.Count);


            var totalDiffObj = new PSObject();
            totalDiffObj.Properties.Add(new PSNoteProperty("Timestamp", firstInfo.Timestamp));
            totalDiffObj.Properties.Add(new PSNoteProperty("TotalBytes", firstInfo.TotalBytes - lastInfo.TotalBytes));
            totalDiffObj.Properties.Add(new PSNoteProperty("HeapCommitted", firstInfo.HeapCommitted - lastInfo.HeapCommitted));
            totalDiffObj.Properties.Add(new PSNoteProperty("UnknownCommitted", firstInfo.UnknownCommitted - lastInfo.UnknownCommitted));

            Log("Creating totalDiff");

            foreach (var stackId in activityStackIds)
            {
                var stack = new PSObject();
                totalDiffObj.Properties.Add(new PSNoteProperty(stackId, totalDiffByStackId[stackId]));
            }


            var intervalDiffs = new List<PSObject>();

            Log("Creating intervalDiffs");

            for (int i = 0; i < allSnapshots.Count; i++)
            {
                var info = allSnapshots[i];
                SnapshotInfo infoNext = null;
                if (i == allSnapshots.Count - 1)
                {
                    infoNext = allSnapshots[i];
                }
                else
                {
                    infoNext = allSnapshots[i + 1];
                }

                var diff = new PSObject();
                diff.Properties.Add(new PSNoteProperty("Timestamp", info.Timestamp));
                diff.Properties.Add(new PSNoteProperty("TotalBytes", info.TotalBytes - infoNext.TotalBytes));
                diff.Properties.Add(new PSNoteProperty("HeapCommitted", info.HeapCommitted - infoNext.HeapCommitted));
                diff.Properties.Add(new PSNoteProperty("UnknownCommitted", info.UnknownCommitted - infoNext.UnknownCommitted));


                foreach (var stackId in activityStackIds)
                {
                    diff.Properties.Add(new PSNoteProperty(stackId, info.Stacks[stackId].Bytes - infoNext.Stacks[stackId].Bytes));
                }

                intervalDiffs.Add(diff);
            }

            Log("sort and get topUsageStackIds");
            var topUsageStackIds = allStackIds.OrderByDescending(x => firstInfo.Stacks[x].Bytes).Take(maxStackCount).ToList();

            var collectedStackIds = new HashSet<string>(activityStackIds);
            collectedStackIds.UnionWith(topUsageStackIds);

            var collectedStacks = new Dictionary<string, PSObject>();

            foreach(var stackId in collectedStackIds)
            {
                var stackInfo = allStackTexts[stackId];
                var stackObj = new PSObject();
                stackObj.Properties.Add(new PSNoteProperty("StackId", stackInfo.StackId));
                stackObj.Properties.Add(new PSNoteProperty("TotalSize", allSnapshots.Select(x => x.Stacks[stackId].Bytes).ToList()));
                stackObj.Properties.Add(new PSNoteProperty("BlockCount", allSnapshots.Select(x => x.Stacks[stackId].Count).ToList()));
                stackObj.Properties.Add(new PSNoteProperty("MaxBlockSize", stackInfo.AllocationMaxBytes));
                stackObj.Properties.Add(new PSNoteProperty("MinBlockSize", stackInfo.AllocationMinBytes));
                stackObj.Properties.Add(new PSNoteProperty("StackText", stackInfo.StackText));
                collectedStacks.Add(stackId, stackObj);
            }



            var result = new PSObject();
            result.Properties.Add(new PSNoteProperty("Handle", firstInfo.Handle));
            result.Properties.Add(new PSNoteProperty("TotalDiffs", totalDiffObj));
            result.Properties.Add(new PSNoteProperty("IntervalDiffs", intervalDiffs));
            result.Properties.Add(new PSNoteProperty("ActivityStackIds", activityStackIds));
            result.Properties.Add(new PSNoteProperty("TopUsageStackIds", topUsageStackIds));
            result.Properties.Add(new PSNoteProperty("Stacks", collectedStacks));
            result.Properties.Add(new PSNoteProperty("TotalBytes", allSnapshots.Select(x => x.TotalBytes).ToList()));
            result.Properties.Add(new PSNoteProperty("UnknownCommitted", allSnapshots.Select(x => x.UnknownCommitted).ToList()));
            result.Properties.Add(new PSNoteProperty("HeapCommitted", allSnapshots.Select(x => x.HeapCommitted).ToList()));
            Log("Analyze done");
            return result;
        }
    }
}
