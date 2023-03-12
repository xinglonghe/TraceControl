using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TraceAnalyzer
{
    public class SnapshotInfo
    {
        public long Handle;
        public DateTime Timestamp;
        public long TotalBytes;
        public Dictionary<string, StackByteCount> Stacks = new Dictionary<string, StackByteCount>();
        public long HeapCommitted;
        public long UnknownCommitted;
    }
}
