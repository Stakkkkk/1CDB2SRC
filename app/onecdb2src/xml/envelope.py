"""Validate a complete XML stream while retaining only the readback envelope."""
from dataclasses import dataclass
from xml.parsers import expat
import xml.etree.ElementTree as ET

MD='{http://v8.1c.ru/8.3/MDClasses}'

def expanded(name):
    return '{'+name if '}' in name else name

@dataclass(frozen=True)
class Envelope:
    tag:str
    attributes:dict
    direct_configurations:int

    def get(self,key,default=None):
        return self.attributes.get(key,default)

class EnvelopeParser:
    def __init__(self, *, count_configurations=False):
        # Match ElementTree's namespace separator and its namespace rejection boundary.
        self.parser=expat.ParserCreate(namespace_separator='}')
        self.tag=None;self.attributes=None;self.depth=0;self.configurations=0
        self.count_configurations=count_configurations
        self.parser.StartElementHandler=self.start
        if count_configurations:self.parser.EndElementHandler=self.end
        # ElementTree does not resolve external general entities either.
        self.parser.ExternalEntityRefHandler=lambda *args:0
        self.parser.SkippedEntityHandler=self.skipped_entity
        self.closed=False

    def start(self,name,attributes):
        tag=expanded(name)
        if self.tag is None:
            self.tag=tag;self.attributes={expanded(k):v for k,v in attributes.items()}
            if not self.count_configurations:
                self.parser.StartElementHandler=None
                return
        elif self.depth==1 and tag==MD+'Configuration':
            self.configurations+=1
        self.depth+=1

    def end(self,name):
        self.depth-=1

    def skipped_entity(self,name,is_parameter_entity):
        if not is_parameter_entity:
            line,column=self.parser.CurrentLineNumber,self.parser.CurrentColumnNumber
            error=ET.ParseError(f'undefined entity &{name};: line {line}, column {column}')
            error.code=expat.errors.codes[expat.errors.XML_ERROR_UNDEFINED_ENTITY]
            error.position=(line,column)
            raise error

    def parse(self,data,final):
        try:self.parser.Parse(data,final)
        except expat.ExpatError as error:
            converted=ET.ParseError(str(error));converted.code=error.code
            converted.position=(error.lineno,error.offset)
            raise converted from error

    def feed(self,data):
        if self.closed:raise ValueError('XML parser already closed')
        self.parse(data,False)

    def close(self):
        if self.closed:raise ValueError('XML parser already closed')
        self.closed=True
        try:self.parse(b'',True)
        finally:
            self.parser.StartElementHandler=None
            self.parser.EndElementHandler=None
            self.parser.SkippedEntityHandler=None
            self.parser.ExternalEntityRefHandler=None
        return Envelope(self.tag,self.attributes,self.configurations)
