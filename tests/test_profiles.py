"""Neutral CF fixtures exercise the real parser/catalog and closed profile binding."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import uuid
import zlib

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from onecdb2src import profiles as p
from onecdb2src.nativecf.brace import Atom as A,Reader
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

class ProfileTests(unittest.TestCase):
    def negative(self,mutator,tag='76'):
        root,row=rows(tag)
        mutator(root,row)
        with self.assertRaises(ValueError):p._detect_rows(root,row)

    def test_positive_known_shapes_real_cf_and_all_pairs(self):
        with tempfile.TemporaryDirectory() as td:
            for tag,pair,platform,xml in (('68',None,'8.3.27','2.20'),('76',('3','3'),'8.5.1','2.21'),('76',('3','6'),'8.5.1','2.21'),('76',('2','2'),'8.5.1','2.21')):
                cf=fixture_cf(Path(td)/(tag+str(pair)+'.cf'),tag,pair or ('3','3'))
                profile=p.select(cf)
                self.assertEqual(profile['platform_profile'],platform)
                self.assertEqual(profile['xml_version'],xml)
                self.assertEqual(profile['interface_pair'],None if pair is None else list(pair))
                self.assertEqual(p.validate(profile,cf),profile)
                self.assertEqual(profile['cf_sha256'],hashlib.sha256(cf.read_bytes()).hexdigest())

    def test_override_cannot_cross_profiles(self):
        with tempfile.TemporaryDirectory() as td:
            cf=fixture_cf(Path(td)/'x.cf')
            self.assertEqual(p.select(cf,'8.5.1')['selection_mode'],'explicit')
            for override in ('8.3.27','8.5','unknown',None):
                with self.subTest(override=override),self.assertRaises(ValueError):p.select(cf,override)

    def test_known_newer_writer_for_legacy_storage_keeps_auto_and_hash_binding(self):
        with tempfile.TemporaryDirectory() as td:
            cf=fixture_cf(Path(td)/'old.cf','68')
            auto=p.select(cf);newer=p.select(cf,'8.5.1')
            self.assertEqual((auto['platform_profile'],auto['xml_version']),('8.3.27','2.20'))
            self.assertEqual((newer['platform_profile'],newer['xml_version']),('8.5.1','2.21'))
            self.assertEqual(auto['cf_sha256'],newer['cf_sha256'])
            self.assertNotEqual(auto['profile_id'],newer['profile_id'])
            self.assertEqual(p.validate(newer,cf),newer)
            forged=newer|{'requested_platform':'auto'};forged['profile_id']=p._id(forged)
            with self.assertRaises(ValueError):p.validate(forged,cf)

    def test_malformed_shape_tag_arity_and_nested_decoy(self):
        for mutation in (lambda r,v:v[3][1][1].append(a(0)),lambda r,v:v[3][1][1].pop(),lambda r,v:v[3][1][1].__setitem__(0,a(67)),lambda r,v:v[3][1][1].__setitem__(0,q('76')),lambda r,v:v[3][1].__setitem__(1,[a(0),v[3][1][1]])):
            self.negative(mutation)

    def test_root_pointer_count_uuid_and_outer_arity(self):
        for mutation in (lambda r,v:r.__setitem__(1,u(999)),lambda r,v:v[1].append(u(5)),lambda r,v:v.__setitem__(2,q('7')),lambda r,v:v.__setitem__(2,a('07')),lambda r,v:v.__setitem__(2,a(6)),lambda r,v:v.pop()):
            self.negative(mutation)

    def test_section_classes_order_wrappers_and_owner_identity(self):
        for mutation in (lambda r,v:v[3].__setitem__(0,a(p.SECTIONS[1][0])),lambda r,v:v[4][1].__setitem__(0,a(1)),lambda r,v:v[5][1][1].__setitem__(0,a(1)),lambda r,v:v[6][1][1].append(identity(8)),lambda r,v:v[4][1][1][1].__setitem__(1,u(55)),lambda r,v:v[5][1][1][1].__setitem__(2,u(1))):
            self.negative(mutation)

    def test_slot_count_membership_duplicate_and_child_count(self):
        for mutation in (lambda r,v:v[3][1].__setitem__(2,a(0)),lambda r,v:v[3][1][3].__setitem__(0,u(999)),lambda r,v:v[3][1].__setitem__(4,copy.deepcopy(v[3][1][3])),lambda r,v:v[3][1][3].__setitem__(1,a(1)),lambda r,v:v[3][1][3].extend([u(5)])):
            self.negative(mutation)

    def test_header_exact_quoted_states_synonym_counts(self):
        for mutation in (lambda r,v:v[3][1][1][1][1].__setitem__(2,a('name')),lambda r,v:v[3][1][1][1][1].__setitem__(0,a(2)),lambda r,v:v[3][1][1][1][1].__setitem__(6,a(1)),lambda r,v:v[3][1][1][1][1].__setitem__(3,[a(1),q('ru')]),lambda r,v:v[3][1][1][1][1][1].__setitem__(0,a(0))):
            self.negative(mutation)

    def test_interface_pair_exact_unquoted_single_digits(self):
        for value in (q('3'),a('03'),a('+3'),a(4),[a(3)]):
            self.negative(lambda r,v,value=value:v[3][1][1].__setitem__(38,value))
        self.negative(lambda r,v:v[3][1][1].__setitem__(62,a(2)))

    def test_v76_tail_defaults_and_compatibility_guards(self):
        for mutation in (lambda r,v:v[3][1][1].__setitem__(77-1,a(0)),lambda r,v:v[3][1][1].__setitem__(67,a(1)),lambda r,v:v[3][1][1].__setitem__(60,a(0)),lambda r,v:v[3][1][1].__setitem__(43,a(80324))):
            self.negative(mutation)
        r,v=rows();v[3][1][1][43]=a(80501)
        self.assertEqual(p._detect_rows(r,v)['platform_profile'],'8.5.1')

    def test_footer_variants_and_invalid_checksum(self):
        r,v=rows()
        for footer in ([[a(0),q('key'),q('sig')]],[[a(1),q(''),q('')],[a(-2147483648)]]):
            v[-1]=footer;self.assertEqual(p._detect_rows(r,v)['shape_tag'],'76')
        for footer in ([[a(1),q(''),q('')],[a(2147483648)]],[[a(0),q('key'),q('')]],[[a(0),a(''),q('')]]):
            self.negative(lambda r,v,footer=footer:v.__setitem__(-1,footer))

    def test_receipt_closed_keys_id_duplicate_json_exclusive_and_cf_tamper(self):
        with tempfile.TemporaryDirectory() as td:
            cf=fixture_cf(Path(td)/'x.cf');profile=p.select(cf);receipt=Path(td)/'profile.json'
            p.save_new(receipt,profile)
            self.assertEqual(p.load(receipt,cf),profile)
            with self.assertRaises(FileExistsError):p.save_new(receipt,profile)
            for changed in (profile|{'new':1},profile|{'profile_id':'0'*64},profile|{'platform_profile':'8.3.27'},profile|{'cf_bytes':True}):
                with self.assertRaises(ValueError):p.validate(changed,cf)
            receipt.write_text('{"schema":1,"schema":1}')
            with self.assertRaises(ValueError):p.load(receipt,cf)
            with cf.open('ab') as stream:stream.write(b'tampered')
            with self.assertRaises(ValueError):p.validate(profile,cf)

    def test_rehashed_forgery_wrong_path_tool_binding_and_reselection(self):
        with tempfile.TemporaryDirectory() as td:
            cf=fixture_cf(Path(td)/'x.cf');profile=p.select(cf)
            for key,value in (('platform_profile','8.3.27'),('detector_sha256','f'*64),('shape_arity',61),('requested_platform','8.3.27')):
                changed=profile|{key:value};changed['profile_id']=p._id(changed)
                with self.assertRaises(ValueError):p.validate(changed,cf)
            other=Path(td)/'other.cf';other.write_bytes(cf.read_bytes())
            with self.assertRaises(ValueError):p.validate(profile,other)

if __name__=='__main__':unittest.main()
