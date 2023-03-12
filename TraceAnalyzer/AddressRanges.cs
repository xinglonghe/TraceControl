using Microsoft.Windows.EventTracing;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TraceAnalyzer
{
    public delegate void Logger(string formatStr, params object[] args);

    public class AddressRanges
    {
        private Logger Log;

        public LinkedList<AddrRange> Ranges { get; set; } = new LinkedList<AddrRange>();


        public AddressRanges(Logger logger)
        {
            this.Log = logger;
        }

        public long TotalBytes {
            get {
                long totalBytes = 0;
                foreach(var range in this.Ranges)
                {
                    totalBytes += (long)(range.End - range.Start);
                }
                return totalBytes;
            }
        }


        public void AddRange(AddrRange range)
        {
            var list = this.Ranges;

            if (!list.Any() || list.Last.Value.End < range.Start)
            {
                //append.
                list.AddLast(range);
                return;
            }

            if (list.Last.Value.Start <= range.Start)
            {
                // merge to last;
                list.Last.Value.End = Math.Max(list.Last.Value.End, range.End);
                return;
            }

            var current = list.First;
            while(current != null && current.Value.Start <= range.Start)
            {
                current = current.Next;
            }

            if (current == null)
            {
                current = list.Last;
            }
            else
            {
                current = current.Previous;
            }

            if (current == null)
            {
                list.AddFirst(range);
                current = list.First;
            }
            else if (current.Value.End >= range.Start)
            {
                current.Value.End = Math.Max(current.Value.End, range.End);
            }
            else
            {
                list.AddAfter(current, range);
                current = current.Next;
            }

            while(current.Next != null && current.Value.End >= current.Next.Value.Start)
            {
                current.Value.End = Math.Max(current.Value.End, current.Next.Value.End);
                list.Remove(current.Next);
            }
        }


        public void RemoveRange(AddrRange range)
        {
            if (!this.Ranges.Any() || this.Ranges.Last.Value.End <= range.Start || this.Ranges.First.Value.Start >= range.End)
            {
                return;
            }

            var current = this.Ranges.First;
            while(current != null)
            {
                if (current.Value.Start < range.Start)
                {
                    if (current.Value.End <= range.Start)
                    {
                        current = current.Next;
                    }
                    else if (current.Value.End > range.Start && current.Value.End <= range.End)
                    {
                        current.Value.End = range.Start;
                        current = current.Next;
                    }
                    else
                    {
                        // cut into two
                        var newItem = new AddrRange() {
                            Timestamp = current.Value.Timestamp,
                            ThreadId = current.Value.ThreadId,
                            Start = range.End,
                            End = current.Value.End
                        };

                        current.Value.End = range.Start;

                        this.Ranges.AddAfter(current, newItem);
                        break;
                    }

                }
                else if (current.Value.Start >= range.Start && current.Value.Start < range.End)
                {
                    if (current.Value.End <= range.End)
                    {
                        var temp = current;
                        current = current.Next;
                        this.Ranges.Remove(temp);
                    }
                    else
                    {
                        current.Value.Start = range.End;
                        break;
                    }
                }
                else
                {
                    // outside the range at the end.
                    break;
                }
            }
        }
    }

    public class AddrRange
    {
        public ulong Start;
        public ulong End;
        public TraceTimestamp Timestamp;
        public int ThreadId;
    }
}
