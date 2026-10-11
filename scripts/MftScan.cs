using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace DiskAudit
{
    public class MftException : Exception
    {
        public string Code { get; private set; }
        public MftException(string code, string message) : base(message) { this.Code = code; }
    }

    public class MftBucket
    {
        public int Depth;
        public string Path;
        public long Bytes;
        public long Files;
        public long Dirs;
    }

    public class MftFileRef
    {
        public string Path;
        public long Bytes;
        public long MtimeTicks;
    }

    // Size of one directory subtree that the caller asked for by name. Produced by
    // the same pass that builds the buckets, so the numbers agree with the snapshot.
    public class MftTargetSize
    {
        public string Path;
        public long Bytes;
        public long Files;
        public long Dirs;
    }

    public class MftRootResult
    {
        public string Root = "";
        public long TotalBytes;
        public long Files;
        public long Dirs;
        public long Orphans;
        public long ExtensionRecords;
        public long AttributeListRecords;
        public long HardLinkEntries;
        public long MetadataSkipped;
        public long RecordCount;
        public long NameSizeFallbackFiles;
        public long DiagSig;
        public long DiagInUse;
        public long DiagBase;
        public long DiagNoName;
        public long DiagNs0;
        public long DiagNs1;
        public long DiagNs2;
        public long DiagNs3;
        public long DiagNoDataAttr;
        public long DiagZeroSizeFiles;
        public long DiagEntries;
        public long DiagExtEntries;
        public long DiagExtEmpty;
        public string FileSystem = "NTFS";
        public List<MftBucket> Buckets = new List<MftBucket>();
        public List<MftFileRef> BigFiles = new List<MftFileRef>();
        public List<MftFileRef> NotableFiles = new List<MftFileRef>();
        public List<MftTargetSize> TargetSizes = new List<MftTargetSize>();
        public long TargetedPaths;
    }

    public static class MftScanner
    {
        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 1;
        private const uint FILE_SHARE_WRITE = 2;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000;
        private const int SECTOR_ALIGN = 4096;
        private const int READ_CHUNK = 4194304;
        private const ulong REC_MASK = 0x0000FFFFFFFFFFFFUL;
        private const int ROOT_RECORD = 5;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafeFileHandle CreateFileW(string name, uint access, uint share,
            IntPtr sa, uint disp, uint flags, IntPtr templ);

        private struct Run
        {
            public long Lcn;
            public long Clusters;
        }

        private struct Entry
        {
            public int Rec;
            public int ParentRec;
            public string Name;
        }

        private struct Frame
        {
            public int Rec;
            public int Depth;
            public string Path;
        }

        private class Volume : IDisposable
        {
            private readonly FileStream _fs;

            public Volume(string volumePath)
            {
                SafeFileHandle h = CreateFileW(volumePath, GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING,
                    FILE_FLAG_SEQUENTIAL_SCAN, IntPtr.Zero);
                if (h.IsInvalid)
                {
                    int err = Marshal.GetLastWin32Error();
                    if (err == 5)
                        throw new MftException("access_denied",
                            "cannot open " + volumePath + " for raw reading (administrator rights required)");
                    throw new MftException("open_failed",
                        "cannot open " + volumePath + " (win32 error " + err + ")");
                }
                _fs = new FileStream(h, FileAccess.Read, SECTOR_ALIGN, false);
            }

            public void ReadExact(long offset, byte[] buf, int count)
            {
                _fs.Seek(offset, SeekOrigin.Begin);
                int done = 0;
                while (done < count)
                {
                    int n = _fs.Read(buf, done, count - done);
                    if (n <= 0) break;
                    done += n;
                }
                for (int i = done; i < count; i++) buf[i] = 0;
            }

            public byte[] ReadAligned(long offset, int count)
            {
                long aligned = offset & ~((long)SECTOR_ALIGN - 1);
                int delta = (int)(offset - aligned);
                int need = delta + count;
                int alen = (need + SECTOR_ALIGN - 1) & ~(SECTOR_ALIGN - 1);
                if (delta == 0 && alen == count)
                {
                    byte[] exact = new byte[count];
                    ReadExact(aligned, exact, count);
                    return exact;
                }
                byte[] tmp = new byte[alen];
                ReadExact(aligned, tmp, alen);
                byte[] res = new byte[count];
                Buffer.BlockCopy(tmp, delta, res, 0, count);
                return res;
            }

            public void Dispose() { _fs.Dispose(); }
        }

        private class MftStream
        {
            private readonly Volume _vol;
            private readonly List<Run> _runs;
            private readonly int _cluster;
            private readonly long _length;
            private int _cur;
            private long _runStart;

            public MftStream(Volume vol, List<Run> runs, int cluster, long length)
            {
                _vol = vol; _runs = runs; _cluster = cluster; _length = length;
            }

            public int ReadLogical(long off, byte[] dst, int len)
            {
                int done = 0;
                while (done < len)
                {
                    long logical = off + done;
                    if (logical >= _length) break;

                    while (_cur < _runs.Count)
                    {
                        long runBytes = _runs[_cur].Clusters * _cluster;
                        if (logical < _runStart + runBytes) break;
                        _runStart += runBytes;
                        _cur++;
                    }
                    if (_cur >= _runs.Count) break;

                    long inRun = logical - _runStart;
                    long avail = _runs[_cur].Clusters * _cluster - inRun;
                    if (avail <= 0) { _cur++; continue; }
                    int chunk = (int)Math.Min(len - done, avail);
                    long volOff = _runs[_cur].Lcn * _cluster + inRun;
                    byte[] part = _vol.ReadAligned(volOff, chunk);
                    Buffer.BlockCopy(part, 0, dst, done, chunk);
                    done += chunk;
                }
                return done;
            }
        }

        private static void ApplyFixup(byte[] buf, int off, int recSize, int sector)
        {
            int usaOff = BitConverter.ToUInt16(buf, off + 4);
            int usaCount = BitConverter.ToUInt16(buf, off + 6);
            if (usaCount < 2) return;
            int usaAbs = off + usaOff;
            if (usaAbs < 0 || usaAbs + usaCount * 2 > off + recSize) return;
            for (int i = 1; i < usaCount; i++)
            {
                int target = off + i * sector - 2;
                if (target < off || target + 2 > off + recSize) break;
                buf[target] = buf[usaAbs + i * 2];
                buf[target + 1] = buf[usaAbs + i * 2 + 1];
            }
        }

        private static void ParseRecord(byte[] buf, int off, int recSize, int sector,
            List<ulong> nParents, List<string> nNames, List<int> nNs,
            out long mtime, out bool isDir, out long dataSize, out long nameSize,
            out bool hasAttrList, out bool isExtension, out bool isFileRecord,
            out bool inUse, out bool hasData, out long baseRec)
        {
            mtime = 0; isDir = false; dataSize = 0; nameSize = 0;
            hasAttrList = false; isExtension = false; isFileRecord = false;
            inUse = false; hasData = false; baseRec = -1;
            nParents.Clear(); nNames.Clear(); nNs.Clear();

            if (buf[off] != 0x46 || buf[off + 1] != 0x49 ||
                buf[off + 2] != 0x4C || buf[off + 3] != 0x45) return;
            isFileRecord = true;

            ApplyFixup(buf, off, recSize, sector);

            int flags = BitConverter.ToUInt16(buf, off + 0x16);
            if ((flags & 0x0001) == 0) return;
            inUse = true;
            isDir = (flags & 0x0002) != 0;

            ulong baseRef = BitConverter.ToUInt64(buf, off + 0x20);
            if ((baseRef & REC_MASK) != 0)
            {
                // Extension record: its attributes belong to the base record. Files
                // with many hard links keep only a few $FILE_NAME attributes in the
                // base record and push the rest here, so these MUST be read as well.
                isExtension = true;
                baseRec = (long)(baseRef & REC_MASK);
            }

            int p = off + BitConverter.ToUInt16(buf, off + 0x14);
            int end = off + recSize;

            while (p + 8 <= end)
            {
                int type = BitConverter.ToInt32(buf, p);
                if (type == -1) break;
                int len = BitConverter.ToInt32(buf, p + 4);
                if (len < 16 || p + len > end) break;

                bool nonResident = buf[p + 8] != 0;
                int nameLen = buf[p + 9];

                if (!nonResident)
                {
                    if (p + 24 > end) break;
                }
                else
                {
                    if (p + 0x40 > end) break;
                }

                if (type == 0x10 && !nonResident)
                {
                    int c = p + BitConverter.ToUInt16(buf, p + 20);
                    if (c + 16 <= p + len) mtime = BitConverter.ToInt64(buf, c + 8);
                }
                else if (type == 0x20)
                {
                    hasAttrList = true;
                }
                else if (type == 0x30 && !nonResident)
                {
                    int c = p + BitConverter.ToUInt16(buf, p + 20);
                    if (c + 0x42 <= p + len)
                    {
                        ulong parent = BitConverter.ToUInt64(buf, c);
                        int nlen = buf[c + 0x40];
                        int nspace = buf[c + 0x41];
                        if (c + 0x38 <= p + len)
                        {
                            long rs = BitConverter.ToInt64(buf, c + 0x30);
                            if (rs > nameSize) nameSize = rs;
                        }
                        if (nlen > 0 && c + 0x42 + nlen * 2 <= p + len)
                        {
                            string nm = Encoding.Unicode.GetString(buf, c + 0x42, nlen * 2);
                            nParents.Add(parent);
                            nNames.Add(nm);
                            nNs.Add(nspace);
                        }
                    }
                }
                else if (type == 0x80 && nameLen == 0)
                {
                    hasData = true;
                    if (nonResident)
                    {
                        // 0x30 is the ALLOCATED size and 0x38 the REAL (logical) size.
                        // Compressed and sparse files allocate far less than they
                        // measure, and the walker reports the logical length (as does
                        // Explorer), so the logical size is what keeps the two
                        // engines telling the same story.
                        long allocated = BitConverter.ToInt64(buf, p + 0x30);
                        long real = BitConverter.ToInt64(buf, p + 0x38);
                        long cand = real > 0 ? real : allocated;
                        // A record can hold several $DATA attributes: the one with the
                        // lowest starting VCN carries the size and continuation chunks
                        // report zero. Taking the largest keeps the real size instead
                        // of letting a trailing zero chunk erase it.
                        if (cand > dataSize) dataSize = cand;
                    }
                    else
                    {
                        long cand = BitConverter.ToInt32(buf, p + 16);
                        if (cand > dataSize) dataSize = cand;
                    }
                }

                p += len;
            }
        }

        private static bool TryParseMftDataRuns(byte[] rec, int recSize, int sector,
            List<Run> runs, out long realSize)
        {
            realSize = 0;
            ApplyFixup(rec, 0, recSize, sector);
            if (rec[0] != 0x46) return false;

            int p = BitConverter.ToUInt16(rec, 0x14);
            while (p + 8 <= recSize)
            {
                int type = BitConverter.ToInt32(rec, p);
                if (type == -1) break;
                int len = BitConverter.ToInt32(rec, p + 4);
                if (len < 16 || p + len > recSize) break;

                bool nonResident = rec[p + 8] != 0;
                int nameLen = rec[p + 9];

                if (type == 0x80 && nameLen == 0 && nonResident)
                {
                    if (p + 0x40 > recSize) return false;
                    // Same allocated-vs-real distinction as for file data; the record
                    // array is identified by its logical length.
                    long allocSize = BitConverter.ToInt64(rec, p + 0x30);
                    long logicalSize = BitConverter.ToInt64(rec, p + 0x38);
                    realSize = Math.Max(logicalSize, allocSize);
                    int rlOff = BitConverter.ToUInt16(rec, p + 0x20);
                    int q = p + rlOff;
                    long prevLcn = 0;
                    while (q < recSize && rec[q] != 0)
                    {
                        int lsize = rec[q] & 0x0F;
                        int osize = (rec[q] >> 4) & 0x0F;
                        q++;
                        if (lsize == 0 || osize == 0 || q + lsize + osize > recSize) break;
                        long runLen = 0;
                        for (int i = 0; i < lsize; i++) runLen |= ((long)rec[q + i]) << (8 * i);
                        long runOff = 0;
                        for (int i = 0; i < osize; i++) runOff |= ((long)rec[q + lsize + i]) << (8 * i);
                        if (osize < 8 && (rec[q + lsize + osize - 1] & 0x80) != 0)
                            runOff |= (-1L) << (8 * osize);
                        prevLcn += runOff;
                        Run r = new Run();
                        r.Lcn = prevLcn;
                        r.Clusters = runLen;
                        runs.Add(r);
                        q += lsize + osize;
                    }
                    return runs.Count > 0;
                }
                p += len;
            }
            return false;
        }

        private static string BuildPath(int[] parentRec, string[] recName, int rootRec,
            string letter, int startRec, string leaf)
        {
            List<string> parts = new List<string>(16);
            parts.Add(leaf);
            int c = startRec;
            int guard = 0;
            while (c != rootRec)
            {
                if (++guard > 256) return null;
                if (c < 0 || c >= recName.Length) return null;
                string nm = recName[c];
                if (nm == null) return null;
                parts.Add(nm);
                int up = parentRec[c];
                if (up == c) break;
                c = up;
            }
            parts.Reverse();
            StringBuilder sb = new StringBuilder();
            sb.Append(letter).Append(":\\");
            for (int i = 0; i < parts.Count; i++)
            {
                if (i > 0) sb.Append('\\');
                sb.Append(parts[i]);
            }
            return sb.ToString();
        }

        public static MftRootResult Scan(string letter, int maxDepth, long bigThreshold,
            long notableFloor, int maxBucket, int notableCap)
        {
            return Scan(letter, maxDepth, bigThreshold, notableFloor, maxBucket, notableCap, null);
        }

        // `targets` names directories the caller wants exact subtree sizes for
        // (deep cache directories, for instance, that a snapshot bucket would not
        // reach). They are measured during the same single pass, which is why this
        // costs a fraction of a second instead of a fresh directory walk per path.
        public static MftRootResult Scan(string letter, int maxDepth, long bigThreshold,
            long notableFloor, int maxBucket, int notableCap, string[] targets)
        {
            if (letter == null) throw new ArgumentNullException("letter");
            letter = letter.Trim().TrimEnd('\\', ':').Trim();
            if (letter.Length != 1)
                throw new MftException("bad_root",
                    "the MFT engine requires a volume root such as C:\\ (got '" + letter + "')");

            HashSet<string> wantDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (targets != null)
            {
                for (int i = 0; i < targets.Length; i++)
                {
                    string t = targets[i];
                    if (t == null) continue;
                    t = t.Trim();
                    if (t.StartsWith("\\\\?\\", StringComparison.Ordinal)) t = t.Substring(4);
                    t = t.TrimEnd('\\').Trim();
                    if (t.Length < 2 || t[1] != ':') continue;
                    if (t.Length == 2) t = t + "\\";
                    wantDirs.Add(t);
                }
            }

            MftRootResult res = new MftRootResult();
            res.Root = letter + ":\\";
            res.TargetedPaths = wantDirs.Count;

            using (Volume vol = new Volume(@"\\.\" + letter + ":"))
            {
                byte[] boot = vol.ReadAligned(0, 4096);
                string oem = Encoding.ASCII.GetString(boot, 3, 8);
                if (!oem.StartsWith("NTFS", StringComparison.Ordinal))
                    throw new MftException("not_ntfs",
                        "volume is not NTFS (oem id '" + oem.Trim() + "')");

                int bytesPerSector = BitConverter.ToUInt16(boot, 0x0B);
                int sectorsPerCluster = boot[0x0D];
                long mftLcn = BitConverter.ToInt64(boot, 0x30);
                // 0x40 is a SIGNED BYTE: positive means clusters per record, negative
                // means the record size is 2^(-value) bytes (the normal case, 0xF6 = 1024).
                sbyte recClusters = unchecked((sbyte)boot[0x40]);

                if (bytesPerSector < 256 || bytesPerSector > 4096)
                    throw new MftException("bad_boot", "invalid bytes-per-sector " + bytesPerSector);
                if (sectorsPerCluster < 1 || sectorsPerCluster > 128)
                    throw new MftException("bad_boot", "invalid sectors-per-cluster " + sectorsPerCluster);
                if (recClusters == 0)
                    throw new MftException("bad_boot", "invalid clusters-per-file-record");
                if (mftLcn <= 0)
                    throw new MftException("bad_boot", "invalid MFT start cluster " + mftLcn);

                int cluster = bytesPerSector * sectorsPerCluster;
                int recSize = recClusters > 0 ? recClusters * cluster : (1 << (-recClusters));
                if (recSize < 512 || recSize > 65536)
                    throw new MftException("bad_boot", "invalid file record size " + recSize);
                if (cluster < 512 || (cluster & (cluster - 1)) != 0)
                    throw new MftException("bad_boot", "invalid cluster size " + cluster);

                byte[] rec0 = vol.ReadAligned(mftLcn * cluster, recSize);
                List<Run> runs = new List<Run>(4);
                long mftRealSize;
                if (!TryParseMftDataRuns(rec0, recSize, bytesPerSector, runs, out mftRealSize))
                    throw new MftException("mft_unreadable", "could not resolve the $MFT data runs");

                long runBytes = 0;
                foreach (Run r in runs) runBytes += r.Clusters * cluster;
                long mftBytes = Math.Min(mftRealSize, runBytes);
                if (mftBytes < recSize) throw new MftException("mft_unreadable", "the $MFT is empty");

                int cap = (int)(mftBytes / recSize) + 2;
                res.RecordCount = cap - 2;

                bool[] used = new bool[cap];
                bool[] isDirRec = new bool[cap];
                int[] parentRec = new int[cap];
                long[] recMtime = new long[cap];
                string[] recName = new string[cap];
                // One file can span several MFT records via $ATTRIBUTE_LIST. Every fragment
                // repeats the same stream size, so the fragments are combined with MAX, not SUM.
                long[] sizeMax = new long[cap];
                long[] nameSizeMax = new long[cap];
                for (int i = 0; i < cap; i++) parentRec[i] = -1;

                List<Entry> entries = new List<Entry>(cap);
                List<ulong> nParents = new List<ulong>(4);
                List<string> nNames = new List<string>(4);
                List<int> nNs = new List<int>(4);

                MftStream ms = new MftStream(vol, runs, cluster, mftBytes);
                int chunkSize = recSize * Math.Max(1, READ_CHUNK / recSize);
                byte[] chunk = new byte[chunkSize];

                long extCount = 0, attrListCount = 0, metaSkipped = 0;
                long off = 0;

                while (off < mftBytes)
                {
                    int want = (int)Math.Min(chunkSize, mftBytes - off);
                    int got = ms.ReadLogical(off, chunk, want);
                    if (got < recSize) break;
                    int nrec = got / recSize;

                    for (int i = 0; i < nrec; i++)
                    {
                        int recNo = (int)(off / recSize) + i;
                        if (recNo >= cap) break;

                        long mt, dsz, nsz, baseRec;
                        bool dir, hasAL, isExt, isFileRec, inUse, hasData;
                        ParseRecord(chunk, i * recSize, recSize, bytesPerSector,
                                    nParents, nNames, nNs,
                                    out mt, out dir, out dsz, out nsz, out hasAL,
                                    out isExt, out isFileRec, out inUse, out hasData, out baseRec);

                        if (!isFileRec) continue;
                        res.DiagSig++;
                        if (!inUse) continue;
                        res.DiagInUse++;

                        for (int k = 0; k < nNs.Count; k++)
                        {
                            if (nNs[k] == 0) res.DiagNs0++;
                            else if (nNs[k] == 1) res.DiagNs1++;
                            else if (nNs[k] == 2) res.DiagNs2++;
                            else if (nNs[k] == 3) res.DiagNs3++;
                        }

                        if (isExt)
                        {
                            extCount++;
                            if (baseRec < 0 || baseRec >= cap) continue;
                            if (dsz > sizeMax[baseRec]) sizeMax[baseRec] = dsz;
                            if (nsz > nameSizeMax[baseRec]) nameSizeMax[baseRec] = nsz;
                            int before = entries.Count;
                            AddNameEntries(entries, nParents, nNames, nNs, (int)baseRec);
                            int addedNow = entries.Count - before;
                            res.DiagExtEntries += addedNow;
                            if (addedNow == 0) res.DiagExtEmpty++;
                            continue;
                        }

                        res.DiagBase++;
                        if (recNo < 16 && recNo != ROOT_RECORD) { metaSkipped++; continue; }
                        if (nNames.Count == 0)
                        {
                            // A record can run out of room - a $DATA attribute with a long
                            // run list plus an $ATTRIBUTE_LIST, say - and have its $FILE_NAME
                            // pushed into an extension record. The record is still a live
                            // file or directory, so it has to be marked as one: names that
                            // arrive later from the extension record are keyed to THIS record
                            // number and get discarded later unless it counts as live.
                            res.DiagNoName++;
                            used[recNo] = true;
                            isDirRec[recNo] = dir;
                            recMtime[recNo] = mt;
                            if (dsz > sizeMax[recNo]) sizeMax[recNo] = dsz;
                            if (nsz > nameSizeMax[recNo]) nameSizeMax[recNo] = nsz;
                            continue;
                        }

                        if (hasAL) attrListCount++;
                        used[recNo] = true;
                        isDirRec[recNo] = dir;
                        recMtime[recNo] = mt;
                        if (dsz > sizeMax[recNo]) sizeMax[recNo] = dsz;
                        if (nsz > nameSizeMax[recNo]) nameSizeMax[recNo] = nsz;

                        if (!dir)
                        {
                            if (!hasData) res.DiagNoDataAttr++;
                            else if (dsz == 0) res.DiagZeroSizeFiles++;
                        }

                        int best = 0;
                        for (int k = 0; k < nNs.Count; k++)
                            if (nNs[k] == 1 || nNs[k] == 3) { best = k; break; }
                        recName[recNo] = nNames[best];
                        if (recNo == ROOT_RECORD) parentRec[recNo] = ROOT_RECORD;
                        else parentRec[recNo] = (int)(nParents[best] & REC_MASK);

                        AddNameEntries(entries, nParents, nNames, nNs, recNo);
                    }
                    off += (long)nrec * recSize;
                }

                res.ExtensionRecords = extCount;
                res.AttributeListRecords = attrListCount;
                res.MetadataSkipped = metaSkipped;

                if (!used[ROOT_RECORD] || !isDirRec[ROOT_RECORD])
                    throw new MftException("no_root_record",
                        "the MFT root directory record (5) was not found");

                // Drop names that belong to records which are not live base records
                // (stale extension fragments, metadata files, reserved records).
                int keep = 0;
                for (int i = 0; i < entries.Count; i++)
                {
                    Entry e = entries[i];
                    if (e.Rec < 0 || e.Rec >= cap || !used[e.Rec]) continue;
                    entries[keep++] = e;
                }
                if (keep < entries.Count) entries.RemoveRange(keep, entries.Count - keep);

                long baseWithNames = 0;
                for (int i = 0; i < cap; i++) if (used[i]) baseWithNames++;
                res.DiagEntries = entries.Count;
                res.HardLinkEntries = entries.Count - baseWithNames;

                int[] cnt = new int[cap];
                for (int i = 0; i < entries.Count; i++)
                {
                    int pr = entries[i].ParentRec;
                    if (pr >= 0 && pr < cap) cnt[pr]++;
                }
                int[] offs = new int[cap];
                int acc = 0;
                for (int i = 0; i < cap; i++) { offs[i] = acc; acc += cnt[i]; }
                int[] idx = new int[acc];
                int[] cursor = new int[cap];
                Array.Copy(offs, cursor, cap);
                for (int i = 0; i < entries.Count; i++)
                {
                    int pr = entries[i].ParentRec;
                    if (pr >= 0 && pr < cap) idx[cursor[pr]++] = i;
                }

                int[] depth = new int[cap];
                bool[] reach = new bool[cap];
                for (int i = 0; i < cap; i++) depth[i] = -1;
                int[] queue = new int[cap];
                int qh = 0, qt = 0;
                queue[qt++] = ROOT_RECORD;
                reach[ROOT_RECORD] = true;
                depth[ROOT_RECORD] = 0;
                long dirCount = 0;

                while (qh < qt)
                {
                    int r = queue[qh++];
                    int stop = offs[r] + cnt[r];
                    for (int j = offs[r]; j < stop; j++)
                    {
                        Entry e = entries[idx[j]];
                        if (!isDirRec[e.Rec]) continue;
                        int cr = e.Rec;
                        if (cr == r || cr < 0 || cr >= cap) continue;
                        if (reach[cr]) continue;
                        reach[cr] = true;
                        depth[cr] = depth[r] + 1;
                        dirCount++;
                        if (qt < cap) queue[qt++] = cr;
                    }
                }

                long[] subtree = new long[cap];
                long[] subFiles = new long[cap];
                long[] subDirs = new long[cap];
                long fileCount = 0, totalBytes = 0, orphanCount = 0;
                long nameFallback = 0;

                for (int i = 0; i < entries.Count; i++)
                {
                    Entry e = entries[i];
                    if (isDirRec[e.Rec]) continue;
                    int pr = e.ParentRec;
                    if (pr < 0 || pr >= cap || !reach[pr]) { orphanCount++; continue; }

                    long sz = sizeMax[e.Rec];
                    if (sz <= 0 && nameSizeMax[e.Rec] > 0)
                    {
                        sz = nameSizeMax[e.Rec];
                        nameFallback++;
                    }

                    fileCount++;
                    totalBytes += sz;

                    int c = pr;
                    while (true)
                    {
                        subtree[c] += sz;
                        subFiles[c]++;
                        if (c == ROOT_RECORD) break;
                        int up = parentRec[c];
                        if (up < 0 || up == c || up >= cap || !reach[up]) break;
                        c = up;
                    }
                }
                res.NameSizeFallbackFiles = nameFallback;

                for (int i = 0; i < cap; i++)
                {
                    if (!isDirRec[i] || !reach[i] || i == ROOT_RECORD) continue;
                    int c = i;
                    int guard = 0;
                    while (c != ROOT_RECORD && guard++ < 512)
                    {
                        subDirs[c]++;
                        int up = parentRec[c];
                        if (up < 0 || up == c || up >= cap || !reach[up]) break;
                        c = up;
                    }
                }

                List<MftBucket> raw = new List<MftBucket>();
                List<Frame> stack = new List<Frame>();
                // With targets in play the walk must reach any depth, because the
                // caller's directories are usually far below the bucket depth.
                string volPrefix = letter + ":\\";
                int walkDepth = wantDirs.Count > 0 ? int.MaxValue : maxDepth;
                if (wantDirs.Count > 0 && wantDirs.Contains(volPrefix))
                {
                    MftTargetSize rootTs = new MftTargetSize();
                    rootTs.Path = volPrefix;
                    rootTs.Bytes = subtree[ROOT_RECORD];
                    rootTs.Files = subFiles[ROOT_RECORD];
                    rootTs.Dirs = subDirs[ROOT_RECORD];
                    res.TargetSizes.Add(rootTs);
                }
                int rootStop = offs[ROOT_RECORD] + cnt[ROOT_RECORD];
                for (int j = offs[ROOT_RECORD]; j < rootStop; j++)
                {
                    Entry e = entries[idx[j]];
                    if (!isDirRec[e.Rec]) continue;
                    Frame f = new Frame();
                    f.Rec = e.Rec; f.Depth = 1; f.Path = e.Name;
                    stack.Add(f);
                }

                while (stack.Count > 0)
                {
                    int last = stack.Count - 1;
                    Frame f = stack[last];
                    stack.RemoveAt(last);

                    long sb = subtree[f.Rec];
                    if (sb > 0 && f.Depth <= maxDepth)
                    {
                        MftBucket b = new MftBucket();
                        b.Depth = f.Depth;
                        b.Path = f.Path;
                        b.Bytes = sb;
                        b.Files = subFiles[f.Rec];
                        b.Dirs = subDirs[f.Rec];
                        raw.Add(b);
                    }
                    if (wantDirs.Count > 0 && wantDirs.Contains(volPrefix + f.Path))
                    {
                        MftTargetSize ts = new MftTargetSize();
                        ts.Path = volPrefix + f.Path;
                        ts.Bytes = sb;
                        ts.Files = subFiles[f.Rec];
                        ts.Dirs = subDirs[f.Rec];
                        res.TargetSizes.Add(ts);
                    }
                    if (f.Depth >= walkDepth) continue;

                    string prefix = f.Path + "\\";
                    int stop = offs[f.Rec] + cnt[f.Rec];
                    for (int j = offs[f.Rec]; j < stop; j++)
                    {
                        Entry e = entries[idx[j]];
                        if (!isDirRec[e.Rec]) continue;
                        Frame nf = new Frame();
                        nf.Rec = e.Rec; nf.Depth = f.Depth + 1; nf.Path = prefix + e.Name;
                        stack.Add(nf);
                    }
                }

                Dictionary<int, List<MftBucket>> byDepth = new Dictionary<int, List<MftBucket>>();
                for (int i = 0; i < raw.Count; i++)
                {
                    MftBucket b = raw[i];
                    List<MftBucket> l;
                    if (!byDepth.TryGetValue(b.Depth, out l))
                    {
                        l = new List<MftBucket>();
                        byDepth[b.Depth] = l;
                    }
                    l.Add(b);
                }
                List<int> depthKeys = new List<int>(byDepth.Keys);
                depthKeys.Sort();
                for (int i = 0; i < depthKeys.Count; i++)
                {
                    List<MftBucket> l = byDepth[depthKeys[i]];
                    l.Sort(delegate(MftBucket a, MftBucket b) { return b.Bytes.CompareTo(a.Bytes); });
                    int n = Math.Min(maxBucket, l.Count);
                    for (int j = 0; j < n; j++) res.Buckets.Add(l[j]);
                }

                for (int i = 0; i < entries.Count; i++)
                {
                    Entry e = entries[i];
                    if (isDirRec[e.Rec]) continue;
                    int pr = e.ParentRec;
                    if (pr < 0 || pr >= cap || !reach[pr]) continue;

                    long sz = sizeMax[e.Rec];
                    if (sz <= 0 && nameSizeMax[e.Rec] > 0) sz = nameSizeMax[e.Rec];
                    if (sz < notableFloor) continue;

                    string abs = BuildPath(parentRec, recName, ROOT_RECORD, letter, pr, e.Name);
                    if (abs == null) continue;

                    MftFileRef fr = new MftFileRef();
                    fr.Path = abs;
                    fr.Bytes = sz;
                    fr.MtimeTicks = recMtime[e.Rec];

                    if (res.NotableFiles.Count < notableCap) res.NotableFiles.Add(fr);
                    if (sz >= bigThreshold) res.BigFiles.Add(fr);
                }

                res.TotalBytes = totalBytes;
                res.Files = fileCount;
                res.Dirs = dirCount;
                res.Orphans = orphanCount;
            }

            return res;
        }

        // One directory entry per $FILE_NAME, matching what FindFirstFile enumerates.
        // A long name also gets a DOS 8.3 alias in a namespace-2 entry, which is NOT a
        // separate directory entry and must not be counted again; duplicate (parent, name)
        // pairs inside one record are collapsed for the same reason. The root record's
        // own name is ".".
        private static void AddNameEntries(List<Entry> entries, List<ulong> nParents,
            List<string> nNames, List<int> nNs, int recNo)
        {
            int start = entries.Count;
            for (int k = 0; k < nNs.Count; k++)
            {
                if (nNs[k] == 2) continue;
                string plain = nNames[k];
                if (plain == "." || plain == "..") continue;

                int parent = (int)(nParents[k] & REC_MASK);
                if (parent < 0) continue;

                bool dup = false;
                for (int j = start; j < entries.Count; j++)
                {
                    if (entries[j].ParentRec == parent &&
                        string.Equals(entries[j].Name, plain, StringComparison.OrdinalIgnoreCase))
                    { dup = true; break; }
                }
                if (dup) continue;

                Entry e = new Entry();
                e.Rec = recNo;
                e.ParentRec = parent;
                e.Name = plain;
                entries.Add(e);
            }
        }
    }
}
