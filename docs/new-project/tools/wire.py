"""qftp/1 wire decoder producing per-field byte annotations (spec-driven, no bincode)."""
import json, struct
ENC={0:"Identity",1:"Zstd"}; HASH={0:"Blake3"}; FT={0:"Regular",1:"Directory",2:"Symlink",3:"Other"}
CODES={400:"Malformed",401:"Unauthorized",403:"PermissionDenied",404:"NotFound",405:"Unsupported",409:"AlreadyExists",413:"FileTooLarge",416:"InvalidRange",420:"NotADirectory",421:"IsADirectory",422:"ChecksumMismatch",423:"UploadOverflow",424:"UploadTruncated",429:"RateLimited",430:"QuotaExceeded",431:"DecodeError",500:"Internal"}
REQ=[("Ls",[("path","string"),("cursor",("opt","string"))]),("Cd",[("path","string")]),("Pwd",[]),
 ("Get",[("path","string"),("offset","u64"),("length",("opt","u64")),("accept_encoding",("seq",("enum",ENC)))]),
 ("Put",[("path","string"),("size","u64"),("mode","u32"),("offset","u64"),("hash_algorithm",("enum",HASH)),("checksum",("opt",("seq","u8"))),("no_clobber","bool"),("checksum_trailer","bool"),("encoding",("enum",ENC)),("plaintext_size","u64")]),
 ("Mkdir",[("path","string")]),("Rmdir",[("path","string")]),("Rm",[("path","string")]),("Rename",[("from","string"),("to","string")]),
 ("Chmod",[("path","string"),("mode","u32")]),("Stat",[("path","string")]),("Quota",[]),("Quit",[])]
DIRENTRY=[("name","string"),("file_type",("enum",FT)),("size","u64"),("modified","u64"),("mtime_nanos","u32"),("uid","u32"),("gid","u32"),("mode","u32")]
FILESTAT=DIRENTRY[1:]
DETAILS=[("Range",[("offset","u64"),("file_size","u64")]),("Upload",[("received","u64"),("declared","u64")]),("RetryAfter",[("millis","u32")])]
ERRRESP=[("code",("enum",CODES)),("message","string"),("details",("opt",("penum",DETAILS)))]
RESP=[("Ok",[]),("Err",[("error",("struct",ERRRESP))]),("DirListing",[("entries",("seq",("struct",DIRENTRY))),("next_cursor",("opt","string"))]),
 ("Path",[("path","string")]),("FileStat",[("stat",("struct",FILESTAT))]),
 ("FileReady",[("size","u64"),("total_size","u64"),("checksum_follows","bool"),("hash_algorithm",("enum",HASH)),("encoding",("enum",ENC)),("plaintext_size","u64")]),
 ("QuotaInfo",[("used_bytes","u64"),("file_count","u64"),("limit_bytes",("opt","u64"))])]

class Dec:
    def __init__(self,b): self.b=b; self.i=0; self.rows=[]
    def take(self,n,label,val,kind):
        if self.i+n>len(self.b): raise ValueError("truncated at %s"%label)
        raw=self.b[self.i:self.i+n]; self.rows.append((self.i,raw,label,val,kind)); self.i+=n; return raw
    def uint(self,n,label,kind="int"):
        raw=self.b[self.i:self.i+n]; v=int.from_bytes(raw,"little"); self.take(n,label,str(v),kind); return v
    def field(self,name,ty,depth=0):
        pfx=name
        if ty=="u8": return self.uint(1,pfx)
        if ty=="u16": return self.uint(2,pfx)
        if ty=="u32": return self.uint(4,pfx)
        if ty=="u64": return self.uint(8,pfx)
        if ty=="bool":
            raw=self.b[self.i:self.i+1]; v=raw[0]
            if v not in (0,1): raise ValueError("bad bool")
            self.take(1,pfx,"true" if v else "false","bool"); return bool(v)
        if ty=="string":
            n=int.from_bytes(self.b[self.i:self.i+8],"little"); self.take(8,pfx+" (長さ)",f"{n} バイト","len")
            s=self.b[self.i:self.i+n].decode("utf-8"); 
            if n: self.take(n,pfx+" (UTF-8)",json.dumps(s,ensure_ascii=False),"str")
            return s
        if isinstance(ty,tuple):
            k=ty[0]
            if k=="opt":
                tag=self.b[self.i]; self.take(1,pfx+" (Option タグ)","None (0x00)" if tag==0 else "Some (0x01)","tag")
                if tag==0: return None
                if tag!=1: raise ValueError("bad opt tag")
                return self.field(name,ty[1],depth)
            if k=="seq":
                n=int.from_bytes(self.b[self.i:self.i+8],"little"); self.take(8,pfx+" (要素数)",f"{n}","len")
                out=[]
                if ty[1]=="u8":
                    if n: self.take(n,pfx+" (バイト列)",self.b[self.i:self.i+n].hex()[:32]+("…" if n>16 else ""),"bytes")
                    return list(self.b[self.i-n:self.i]) if n else []
                for j in range(n): out.append(self.field(f"{pfx}[{j}]",ty[1],depth+1))
                return out
            if k=="enum":
                raw=self.b[self.i:self.i+4]; v=int.from_bytes(raw,"little"); nm=ty[1].get(v,f"Unknown({v})")
                self.take(4,pfx+" (数値 enum)",f"{v} = {nm}","enum"); return nm
            if k=="struct":
                d={}
                for fn,ft in ty[1]: d[fn]=self.field(f"{pfx}.{fn}",ft,depth+1)
                return d
            if k=="penum":
                v=int.from_bytes(self.b[self.i:self.i+4],"little")
                if v>=len(ty[1]): raise ValueError("unknown discriminant")
                vn,fields=ty[1][v]; self.take(4,pfx+" (判別子)",f"{v} = {vn}","disc")
                d={}
                for fn,ft in fields: d[fn]=self.field(f"{pfx}.{fn}",ft,depth+1)
                return {vn:d}
        raise ValueError(ty)

def decode_frame(wire_hex,kind):
    b=bytes.fromhex(wire_hex); d=Dec(b)
    n=int.from_bytes(b[:4],"big"); d.take(4,"フレーム長 (u32 BE)",f"{n} バイト","len")
    table=REQ if kind=="Request" else RESP
    v=int.from_bytes(b[4:8],"little"); vn,fields=table[v]; d.take(4,f"{kind} 判別子 (u32 LE)",f"{v} = {vn}","disc")
    val={}
    for fn,ft in fields: val[fn]=d.field(fn,ft)
    if d.i!=len(b): raise ValueError("trailing bytes")
    return vn,val,d.rows

if __name__=="__main__":
    import sys
    base=sys.argv[1]
    for f,kind in [("requests.json","Request"),("responses.json","Response"),("error-codes.json","Response")]:
        doc=json.load(open(f"{base}/{f}"))
        for vec in doc["vectors"]:
            vn,val,rows=decode_frame(vec["wire_hex"],kind)
            print(f"{f:18} {vec['name']:28} {vn:12} {len(rows):3} rows  {json.dumps(val,ensure_ascii=False)[:90]}")
