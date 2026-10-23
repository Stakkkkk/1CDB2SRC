"""Tiny neutral CF generator. Synthetic metadata only; never a project/DB fixture.

Uses the same public format fixture as tests/test_profiles.py and the real CF64
writer. Production profile guards remain responsible for accepting the fixture.
"""
import uuid,zlib
from onecdb2src import profiles as p
from onecdb2src.nativecf.brace import Atom as A
from onecdb2src.nativecf.v8container import write_cf64

def u(n):return A(str(uuid.UUID(int=n+1)))
def a(value):return A(str(value))
def q(value):return A(value,quoted=True)
def identity(n):return [a(1),a(0),u(n)]

def serialize(value):
    if type(value) is list:return '{'+','.join(serialize(v) for v in value)+'}'
    if value.quoted:return '"'+str(value).replace('"','""')+'"'
    return str(value)

def rows(tag='76',pair=('3','3')):
    properties=[a(0) for _ in range(77 if tag=='76' else 61)]
    properties[0]=a(tag)
    properties[1]=[a(0),[a(3),identity(1),q('Neutral'),[a(0)],q(''),a(0),a(0),a(p.NIL),a(0)]]
    properties[26]=a(80327);properties[43]=a(80327);properties[60]=a(1)
    if tag=='76':
        properties[38]=a(pair[0]);properties[62]=a(pair[1])
        for i in range(69,77):properties[i]=a(p.NIL)
    result=[a(2),[u(0)],a(7)]
    for index,(class_id,wrapper,slots) in enumerate(p.SECTIONS):
        if wrapper=='properties':owner=properties
        elif wrapper=='directory':owner=[identity(index+1),a(p.NIL)]
        elif wrapper=='zero':owner=[a(0),identity(index+1)]
        else:owner=[identity(index+1)]
        body=[a(1),owner,a(len(slots))]+[[a(s),a(0)] for s in slots]
        if wrapper=='directory':body=[a(6),body]
        result.append([a(class_id),body])
    result.append([[a(0),q(''),q('')]])
    return [a(2),u(0),a('')],result

def fixture_cf(path,tag='76',pair=('3','3'),mutator=None):
    root,row=rows(tag,pair)
    if mutator:mutator(root,row)
    entries=[]
    for name,value in (('root',root),(str(root[1]),row)):
        compressed=zlib.compressobj(wbits=-15)
        data=compressed.compress(serialize(value).encode('utf-8'))+compressed.flush()
        entries.append(dict(name=name,size=len(data),chunks=lambda data=data:iter([data])))
    write_cf64(path,entries)
    return path

