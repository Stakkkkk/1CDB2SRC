from pathlib import Path
import sys,unittest,xml.etree.ElementTree as ET
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from onecdb2src.xml.envelope import EnvelopeParser,MD

class EnvelopeTests(unittest.TestCase):
    def parity(self,data):
        try:
            root=ET.fromstring(data);expected=(root.tag,root.attrib,len(root.findall(MD+'Configuration')))
        except ET.ParseError:expected=None
        for size in (1,7,31,1024*1024):
            for count in (False,True):
                with self.subTest(data=data[:120],chunk=size,count=count):
                    parser=EnvelopeParser(count_configurations=count)
                    if expected is None:
                        with self.assertRaises(ET.ParseError):
                            for start in range(0,len(data),size):parser.feed(data[start:start+size])
                            parser.close()
                    else:
                        for start in range(0,len(data),size):parser.feed(data[start:start+size])
                        value=parser.close()
                        self.assertEqual((value.tag,value.attributes),expected[:2])
                        self.assertEqual(value.direct_configurations,expected[2] if count else 0)


    def test_root_attribute_getter_matches_elementtree_for_assembly(self):
        data=b'<x xmlns="urn:a" version="2.20" name="A &amp; B"/>'
        original=ET.fromstring(data)
        parser=EnvelopeParser();parser.feed(data);value=parser.close()
        self.assertEqual(value.tag,original.tag)
        for name,default in [('version',None),('name',None),('missing',None),('missing','fallback')]:
            self.assertEqual(value.get(name,default),original.get(name,default))

    def test_envelopes_namespaces_and_direct_children(self):
        for xml in ('<r/>','<r version="2.20"><a/></r>',
            '<m:MetaDataObject xmlns:m="http://v8.1c.ru/8.3/MDClasses" version="2.20"><m:Configuration/><m:Other><m:Configuration/></m:Other><m:Configuration/></m:MetaDataObject>',
            '<MetaDataObject xmlns="http://v8.1c.ru/8.3/MDClasses" version="2.21"><Configuration/></MetaDataObject>',
            '<r xmlns="urn:a}b" xmlns:a="urn:attrs" a:version="x"/>',
            '<r><x xmlns="urn:other"><Configuration/></x><Configuration xmlns="http://v8.1c.ru/8.3/MDClasses"/></r>',
            '<?xml version="1.0"?><!--before--><r xml:lang="ru"><![CDATA[<not markup>&]]><?pi x?></r><!--after-->'):
            self.parity(xml.encode())

    def test_dtd_defaults_internal_markup_and_entities(self):
        for xml in ('<!DOCTYPE r [<!ENTITY e "text">]><r>&e;&amp;&#65;</r>',
            '<!DOCTYPE r [<!ATTLIST r version CDATA "2.20">]><r/>',
            '<!DOCTYPE r [<!ENTITY e "<Configuration xmlns=\'http://v8.1c.ru/8.3/MDClasses\'/>">]><r>&e;</r>',
            '<!DOCTYPE r [<!ENTITY a "hello"><!ENTITY b "&a;&a;">]><r>&b;</r>',
            '<!DOCTYPE r [<!ENTITY % attrs "<!ATTLIST r version CDATA \'2.20\'>">%attrs;]><r/>',
            '<!DOCTYPE r [<!NOTATION n SYSTEM "none"><!ENTITY e SYSTEM "none" NDATA n>]><r/>',
            '<!DOCTYPE r [<!NOTATION n SYSTEM "none"><!ENTITY e SYSTEM "none" NDATA n>]><r>&e;</r>',
            '<!DOCTYPE r SYSTEM "file:///does-not-exist"><r/>',
            '<!DOCTYPE r SYSTEM "http://127.0.0.1:1/not-accessed"><r/>',
            '<!DOCTYPE r [<!ENTITY ext SYSTEM "file:///does-not-exist">]><r>&ext;</r>',
            '<!DOCTYPE r SYSTEM "file:///does-not-exist"><r>&missing;</r>',
            '<!DOCTYPE r [<!ENTITY e SYSTEM "http://127.0.0.1:1/not-accessed">]><r>&e;</r>'):
            self.parity(xml.encode())

    def test_encodings_and_normalized_attributes(self):
        for data in ('<?xml version="1.0" encoding="UTF-16"?><r a="тест">Привет</r>'.encode('utf-16'),
            '<?xml version="1.0" encoding="iso-8859-1"?><r>é</r>'.encode('iso-8859-1'),
            '<r a="a\r\nb\tc&#13;d"/>'.encode(),b'\xef\xbb\xbf<r/>'):
            self.parity(data)

    def test_malformed_and_undefined_entities_refuse(self):
        for data in (b'',b'<r>',b'<r/><s/>',b'<r><x></r>',b'<r a="1" a="2"/>',b'<p:r/>',
            b'<r>&unknown;</r>',b'<r>&#0;</r>',b'<r>\x00</r>',b'<r>\xff</r>',b'<r><!-- broken</r>',
            b'<r><![CDATA[broken</r>',b'<!DOCTYPE r [<!ENTITY e "&e;">]><r>&e;</r>',b'<r/><?xml version="1.0"?>'):
            self.parity(data)

    def test_late_error_not_hidden_by_root_capture(self):
        self.parity(b'<r>'+b'<x/>'*10000+b'<broken></r>')

    def test_many_nodes_retains_only_root_summary(self):
        parser=EnvelopeParser();parser.feed(b'<r version="2.20">')
        for _ in range(10000):parser.feed(b'<x a="1">text</x>')
        parser.feed(b'</r>');value=parser.close()
        self.assertEqual(value.tag,'r');self.assertEqual(value.attributes,{'version':'2.20'})
        self.assertEqual(set(vars(value)),{'tag','attributes','direct_configurations'})

    def test_closed_parser_cannot_accept_more_bytes(self):
        parser=EnvelopeParser();parser.feed(b'<r/>');parser.close()
        self.assertIsNone(parser.parser.StartElementHandler)
        self.assertIsNone(parser.parser.EndElementHandler)
        self.assertIsNone(parser.parser.SkippedEntityHandler)
        self.assertIsNone(parser.parser.ExternalEntityRefHandler)
        with self.assertRaises(ValueError):parser.feed(b'<s/>')
        with self.assertRaises(ValueError):parser.close()

    def test_undefined_entity_keeps_error_code_and_position(self):
        data=b'<!DOCTYPE r SYSTEM "not-read">\n<r>&missing;</r>'
        with self.assertRaises(ET.ParseError) as old:ET.fromstring(data)
        for count in (False,True):
            with self.subTest(count=count),self.assertRaises(ET.ParseError) as current:
                parser=EnvelopeParser(count_configurations=count);parser.feed(data);parser.close()
            self.assertEqual(current.exception.code,old.exception.code)
            self.assertEqual(current.exception.position,old.exception.position)
            self.assertIn('line 2, column 3',str(current.exception))

if __name__=='__main__':unittest.main()
