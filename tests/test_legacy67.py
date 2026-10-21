import json,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from test_profiles import rows,fixture_cf,a,q
from onecdb2src import profiles as p
from onecdb2src.sqlcf.export_cf import config_identity

def legacy(root,row):
    props=row[3][1][1];props[0]=a(67);props.pop();props[26]=a(80317);props[43]=a(80317)

class Legacy67Tests(unittest.TestCase):
    def test_real_cf_profile_and_immutable_receipt(self):
        with tempfile.TemporaryDirectory() as t:
            cf=fixture_cf(Path(t)/'neutral.cf','68',mutator=legacy)
            profile=p.select(cf);self.assertEqual((profile['shape_tag'],profile['shape_arity'],profile['platform_profile'],profile['xml_version']),('67',60,'8.3.27','2.20'))
            receipt=Path(t)/'receipt.json';p.save_new(receipt,profile);self.assertEqual(p.load(receipt,cf),profile)
            newer=p.select(cf,'8.5.1');self.assertEqual((newer['platform_profile'],newer['xml_version']),('8.5.1','2.21'));self.assertEqual(p.validate(newer,cf),newer)
    def test_arity_and_tag_refused(self):
        for tag,n in [('67',59),('67',61),('66',60),('68',60),('76',60)]:
            r,v=rows('68');legacy(r,v);h=v[3][1][1];h[0]=a(tag)
            while len(h)>n:h.pop()
            while len(h)<n:h.append(a(0))
            with self.subTest(tag=tag,n=n),self.assertRaises(ValueError):p._detect_rows(r,v)
    def test_quoted_tag_refused(self):
        r,v=rows('68');legacy(r,v);v[3][1][1][0]=q('67')
        with self.assertRaises(ValueError):p._detect_rows(r,v)
    def test_future_compatibility_refused(self):
        for pair in [(80501,80501),(80328,80328)]:
            r,v=rows('68');legacy(r,v);v[3][1][1][26]=a(pair[0]);v[3][1][1][43]=a(pair[1])
            with self.subTest(pair=pair),self.assertRaises(ValueError):p._detect_rows(r,v)
    def test_ordinary_coordinates_independent_for_both_legacy_shapes(self):
        for tag in ('67','68'):
            for first,second in [(80319,80312),(80321,80324),(80310,80327),(80327,80327)]:
                r,v=rows('68')
                if tag=='67':legacy(r,v)
                h=v[3][1][1];h[26]=a(first);h[43]=a(second)
                with self.subTest(tag=tag,first=first,second=second):
                    self.assertEqual(p._detect_rows(r,v)['platform_profile'],'8.3.27')

    def test_outer_guards_not_bypassed(self):
        for change in [lambda r,v:v.__setitem__(2,a(6)),lambda r,v:v[3][1].__setitem__(2,a(0)),lambda r,v:v[3].__setitem__(0,a(p.SECTIONS[1][0]))]:
            r,v=rows('68');legacy(r,v);change(r,v)
            with self.assertRaises(ValueError):p._detect_rows(r,v)
    def test_identity_same_schema_coordinates(self):
        r,v=rows('68');legacy(r,v);v[3][1][1][14]=q('Independent vendor');v[3][1][1][15]=q('9.8.7')
        result=config_identity(v);self.assertEqual((result['name'],result['vendor'],result['version'],result['serialization_version']),('Neutral','Independent vendor','9.8.7','67'))
        v[3][1][1].append(a(1))
        with self.assertRaises(ValueError):config_identity(v)

if __name__=='__main__':unittest.main()
