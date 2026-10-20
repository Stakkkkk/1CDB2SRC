"""Bounded parser for 1C brace serialization, retaining quoted-vs-atom tokens."""
from pathlib import Path

class Atom(str):
    def __new__(cls,value,*,quoted=False,start=0,end=0):
        result=super().__new__(cls,value)
        result.quoted=quoted; result.start=start; result.end=end
        return result

class Reader:
    def __init__(self,data,*,max_bytes=512*1024*1024,max_nodes=5000000,max_depth=128):
        if isinstance(data,bytes):
            if len(data)>max_bytes: raise ValueError('Brace size quota exceeded')
            self.text=data.decode('utf-8-sig')
        else:
            if len(data)>max_bytes or len(data.encode('utf-8'))>max_bytes: raise ValueError('Brace size quota exceeded')
            self.text=data.removeprefix('\ufeff')
        self.pos=0; self.nodes=0; self.max_nodes=max_nodes; self.max_depth=max_depth

    def space(self):
        while self.pos<len(self.text) and self.text[self.pos].isspace(): self.pos+=1

    def value(self,depth=0):
        if depth>=self.max_depth: raise ValueError('Brace nesting quota exceeded')
        self.nodes+=1
        if self.nodes>self.max_nodes: raise ValueError('Brace node quota exceeded')
        self.space(); start=self.pos
        if start==len(self.text): raise ValueError('Unexpected end of brace data')
        char=self.text[start]
        if char=='{':
            self.pos+=1; result=[]; self.space()
            if self.pos<len(self.text) and self.text[self.pos]=='}': self.pos+=1; return result
            while True:
                self.space()
                if self.pos<len(self.text) and self.text[self.pos] in ',}':
                    self.nodes+=1
                    if self.nodes>self.max_nodes: raise ValueError('Brace node quota exceeded')
                    result.append(Atom('',start=self.pos,end=self.pos))
                else: result.append(self.value(depth+1))
                self.space()
                if self.pos==len(self.text): raise ValueError('Unclosed brace list')
                char=self.text[self.pos]; self.pos+=1
                if char=='}': return result
                if char!=',': raise ValueError('Expected brace list delimiter')
        if char=='"':
            self.pos+=1; segment=self.pos; pieces=[]
            while True:
                quote=self.text.find('"',self.pos)
                if quote<0: raise ValueError('Unclosed quoted token')
                if quote+1<len(self.text) and self.text[quote+1]=='"':
                    pieces.append(self.text[segment:quote+1]); self.pos=quote+2; segment=self.pos
                else:
                    pieces.append(self.text[segment:quote]); self.pos=quote+1
                    return Atom(''.join(pieces),quoted=True,start=start,end=self.pos)
        while self.pos<len(self.text) and self.text[self.pos] not in ',{}': self.pos+=1
        if self.pos==start: raise ValueError('Invalid atom')
        return Atom(self.text[start:self.pos].strip(),start=start,end=self.pos)

    def read(self):
        result=self.value(); self.space()
        if self.pos!=len(self.text): raise ValueError('Trailing brace data')
        return result

def walk(value,path=()):
    yield path,value
    if isinstance(value,list):
        for i,child in enumerate(value): yield from walk(child,path+(i,))

def load(path,**kwargs): return Reader(Path(path).read_bytes(),**kwargs).read()
