from pathlib import Path
import random,sys,unittest,xml.etree.ElementTree as ET
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from onecdb2src.xml.envelope import EnvelopeParser,MD

class StreamParityTests(unittest.TestCase):
    def parity(self,data,chunks=(7,32768,1048576)):
        try:
            root=ET.fromstring(data);expected=(root.tag,root.attrib,len(root.findall(MD+'Configuration')));error=None
        except (ET.ParseError,LookupError,ValueError) as failed:expected=None;error=type(failed)
        for count in (False,True):
            for size in chunks:
                with self.subTest(length=len(data),count=count,chunk=size):
                    def parse():
                        parser=EnvelopeParser(count_configurations=count)
                        for offset in range(0,len(data),size):parser.feed(data[offset:offset+size])
                        return parser.close()
                    if error is not None:
                        with self.assertRaises(error):parse()
                    else:
                        value=parse();self.assertEqual((value.tag,value.attributes),expected[:2]);self.assertEqual(value.direct_configurations,expected[2] if count else 0)

    def test_random_trees_and_malformed_mutations(self):
        rng=random.Random(371037)
        for number in range(200):
            root=ET.Element(MD+'MetaDataObject',{'version':rng.choice(('2.20','2.21'))})
            def children(parent,depth):
                if depth==4:return
                for _ in range(rng.randrange(1,4)):
                    name=rng.choice((MD+'Configuration',MD+'Other','Plain','{urn:alternate}Configuration'))
                    child=ET.SubElement(parent,name,{'Name':'А & Б < C','i':str(rng.randrange(100))});child.text='Привет & text'
                    if rng.randrange(3)==0:children(child,depth+1)
            children(root,0)
            data=ET.tostring(root,encoding='utf-16' if number%3==0 else 'utf-8',xml_declaration=True)
            self.parity(data,chunks=(31,1048576))
            if number%5==0:self.parity(data[:-5],chunks=(31,1048576))

    def test_legacy_codepages_and_unsupported_encodings_match(self):
        for name in ('windows-1251','koi8-r','iso-8859-1','utf-16-le','utf-16-be','utf-32','not-a-codec'):
            body='<?xml version="1.0" encoding="'+name+'"?><r name="Тест">Привет</r>'
            if name=='iso-8859-1':body=body.replace('Тест','café').replace('Привет','déjà')
            data=body.encode(name if name!='not-a-codec' else 'utf-8')
            self.parity(data)

    def test_default_namespace_attributes_from_dtd_and_skipped_entities(self):
        for text in ('<!DOCTYPE r [<!ATTLIST r xmlns CDATA "urn:default" version CDATA "2.20">]><r/>',
            '<!DOCTYPE r [<!ENTITY % d "<!ATTLIST r xmlns CDATA \'urn:default\'>">%d;]><r/>',
            '<!DOCTYPE r SYSTEM "not-accessed"><r><![CDATA[&not-an-entity;]]></r>',
            '<!DOCTYPE r SYSTEM "not-accessed"><r a="&missing;"/>',
            '<!DOCTYPE r [<!ENTITY x "<Configuration xmlns=\'http://v8.1c.ru/8.3/MDClasses\'/>">]><r>&x;&x;</r>'):
            self.parity(text.encode())

    def test_large_tokens_text_and_late_errors(self):
        self.parity(b'<r attr="'+b'x'*(3*1024**2)+b'"/>',chunks=(32768,1048576))
        self.parity(b'<r>'+b'x'*(8*1024**2)+b'</r>',chunks=(32768,1048576))
        self.parity(b'<r>'+b'x'*(2*1024**2)+b'</wrong>',chunks=(32768,1048576))

if __name__=='__main__':unittest.main()
