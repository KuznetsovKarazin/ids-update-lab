"""ABI3: signed bounded binary classification tree, float32 raw inputs.

This is an explicitly versioned extension; ABI1/2 LR bytes are unchanged.
"""
from dataclasses import dataclass
import hashlib
import math
import struct
import numpy as np
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from .package import PackageError, canonical_json, ENVELOPE_MAGIC

ABI = 3
PAYLOAD_MAGIC = b"SIDST01\0"
HEADER = struct.Struct("<8sIIII32s16sfI")
NODE = struct.Struct("<hhhHff")
MAX_NODES = 127
MAX_ENVELOPE = 4096

def new_contract(names, units):
    value = dict(contract_version=3, runtime_abi=3, feature_names=list(names),
        input_units=list(units), missing_policy="reject_nonfinite", target="attack_vs_normal",
        pretransform="identity", input_domain="nonnegative_finite_float32",
        model_kind="binary_tree", branch_semantics="float32_value_le_float32_split",
        decision_semantics="float32_probability_gt_float32_threshold")
    contract_hash(value)
    return value

def contract_hash(value):
    keys = {"contract_version", "runtime_abi", "feature_names", "input_units", "missing_policy",
        "target", "pretransform", "input_domain", "model_kind", "branch_semantics", "decision_semantics"}
    if not isinstance(value, dict) or set(value) != keys:
        raise PackageError("tree contract keys")
    names, units = value["feature_names"], value["input_units"]
    if not isinstance(names, list) or not 1 <= len(names) <= 16 or any(not isinstance(x,str) or not x or not x.isascii() for x in names) or len(set(names)) != len(names):
        raise PackageError("tree feature names")
    if not isinstance(units,list) or len(units)!=len(names) or any(not isinstance(x,str) or not x for x in units):
        raise PackageError("tree feature units")
    expected = dict(contract_version=3,runtime_abi=3,missing_policy="reject_nonfinite",target="attack_vs_normal",
        pretransform="identity",input_domain="nonnegative_finite_float32",model_kind="binary_tree",
        branch_semantics="float32_value_le_float32_split",decision_semantics="float32_probability_gt_float32_threshold")
    if any(value[k] != v or type(value[k]) is not type(v) for k,v in expected.items()):
        raise PackageError("tree contract semantics")
    return hashlib.sha256(canonical_json(value)).digest()

@dataclass(frozen=True)
class TreeNode:
    left: int
    right: int
    feature: int
    split: float
    probability: float

@dataclass(frozen=True)
class TreeModel:
    version: int
    release: str
    schema: bytes
    count: int
    threshold: float
    nodes: tuple
    runtime_abi: int = ABI

    def payload(self):
        try:
            r = self.release.encode("ascii")
            if not 1 <= len(r) <= 16 or any(c<33 or c>126 for c in r):
                raise PackageError("tree release")
            if type(self.version) is not int or not 0 < self.version <= 0xffffffff:
                raise PackageError("tree version")
            if type(self.runtime_abi) is not int or self.runtime_abi != ABI or len(self.schema)!=32:
                raise PackageError("tree ABI/schema")
            if type(self.count) is not int or not 1 <= self.count <=16:
                raise PackageError("tree features")
            data = HEADER.pack(PAYLOAD_MAGIC,1,ABI,self.version,self.count,self.schema,r.ljust(16,b"\0"),self.threshold,len(self.nodes))
            for node in self.nodes:
                if any(type(v) is not int for v in (node.left,node.right,node.feature)):
                    raise PackageError("tree node integer type")
                data += NODE.pack(node.left,node.right,node.feature,0,node.split,node.probability)
        except (struct.error,OverflowError,UnicodeError) as exc:
            raise PackageError("invalid representable tree parameter") from exc
        parse_payload(data)
        return data

def parse_payload(data):
    if len(data)<HEADER.size: raise PackageError("truncated tree payload")
    magic,fmt,abi,ver,count,schema,release,threshold,n = HEADER.unpack_from(data)
    if magic != PAYLOAD_MAGIC or fmt != 1 or abi != ABI or ver == 0:
        raise PackageError("tree header")
    if not 1<=count<=16 or not 1<=n<=MAX_NODES or len(data)!=HEADER.size+NODE.size*n:
        raise PackageError("tree dimensions/length")
    identifier,_,tail=release.partition(b"\0")
    if not identifier or any(c<33 or c>126 for c in identifier) or any(tail): raise PackageError("tree release")
    if not math.isfinite(threshold) or not 0<threshold<1: raise PackageError("tree decision threshold")
    nodes=[]; parents=[0]*n
    for i in range(n):
        left,right,feature,reserved,split,p = NODE.unpack_from(data,HEADER.size+i*NODE.size)
        if reserved or not math.isfinite(split) or not math.isfinite(p) or not 0<=p<=1:
            raise PackageError("tree node values")
        if left==right==-1:
            if feature!=-1 or split!=0: raise PackageError("tree leaf structure")
        else:
            if not 0<=left<n or not 0<=right<n or left==right or not 0<=feature<count or split<0:
                raise PackageError("tree branch structure")
            parents[left]+=1; parents[right]+=1
        nodes.append(TreeNode(left,right,feature,split,p))
    if parents[0]!=0 or any(x!=1 for x in parents[1:]): raise PackageError("tree parent counts")
    todo=[0]; seen=set()
    while todo:
        i=todo.pop()
        if i in seen: raise PackageError("tree cycle")
        seen.add(i)
        if nodes[i].left>=0: todo.extend((nodes[i].left,nodes[i].right))
    if len(seen)!=n: raise PackageError("unreachable tree node")
    return TreeModel(ver,identifier.decode("ascii"),schema,count,threshold,tuple(nodes))

def sign(model,key):
    if not isinstance(key,rsa.RSAPrivateKey) or key.key_size!=2048: raise PackageError("RSA2048 required")
    data=model.payload(); signature=key.sign(data,padding.PKCS1v15(),hashes.SHA256())
    return struct.pack("<8sII",ENVELOPE_MAGIC,len(data),256)+data+signature

def verify(envelope,key,expected_schema=None,expected_count=None,expected_abi=ABI):
    if not isinstance(key,rsa.RSAPublicKey) or key.key_size!=2048: raise PackageError("RSA2048 required")
    if not 16<=len(envelope)<=MAX_ENVELOPE: raise PackageError("tree envelope length")
    magic,n,s=struct.unpack_from("<8sII",envelope)
    if magic!=ENVELOPE_MAGIC or s!=256 or len(envelope)!=16+n+s: raise PackageError("tree envelope header")
    try: key.verify(envelope[16+n:],envelope[16:16+n],padding.PKCS1v15(),hashes.SHA256())
    except InvalidSignature as exc: raise PackageError("tree signature") from exc
    model=parse_payload(envelope[16:16+n])
    if expected_schema is not None and model.schema!=expected_schema: raise PackageError("tree schema")
    if expected_count is not None and model.count!=expected_count: raise PackageError("tree feature count")
    if type(expected_abi) is not int or expected_abi!=ABI: raise PackageError("tree ABI")
    return model

def infer(model,raw):
    with np.errstate(over="ignore",invalid="ignore"):
        x=np.asarray(raw,dtype=np.float32)
    if x.ndim!=1 or len(x)!=model.count or not np.isfinite(x).all() or (x<0).any():
        raise PackageError("tree raw domain/count")
    i=0
    for _ in model.nodes:
        node=model.nodes[i]
        if node.left==-1:
            p=float(np.float32(node.probability))
            return p,int(p>np.float32(model.threshold))
        i=node.left if x[node.feature]<=np.float32(node.split) else node.right
    raise PackageError("tree traversal did not terminate")

def infer_many(model,raw):
    rows=[infer(model,row) for row in raw]
    return np.asarray([r[0] for r in rows],dtype=np.float32),np.asarray([r[1] for r in rows],dtype=np.int64)
