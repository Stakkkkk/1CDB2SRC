import pathlib,sys,tempfile,unittest
import hashlib
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'app'))
from onecdb2src.xml.dump_info_modern_r3 import signature_profile_guard,validate_modern_signature_passthrough
from onecdb2src.xml import dump_info_modern_r3 as signature_rules

UID='10000000-0000-4000-8000-000000000123'
class Source:
    def __init__(self,legacy=False):self.files={UID+'.10':b'nonempty original signature bytes'};self.files.update({UID+'.d':b'legacy'} if legacy else {})
    def names(self):return self.files.keys()
    def inflated(self,name):return self.files[name]

class ModernSignatureTests(unittest.TestCase):
    def validate(self,source,entries=None,mutation=None):
        with tempfile.TemporaryDirectory(prefix='signature-gate-') as td:
            path=pathlib.Path(td)/'Ext/MobileClientSignature.bin';path.parent.mkdir();path.write_bytes(source.inflated(UID+'.10'))
            if mutation:mutation(path)
            return validate_modern_signature_passthrough(source,UID,{'xml_version':'2.21'},entries or [{'logical_name':UID+'.10','disposition':'supported','outputs':['Ext/MobileClientSignature.bin']}],pathlib.Path(td))
    def test_nonempty_binary_preserved_without_claiming_cryptographic_validation(self):
        proof=self.validate(Source());self.assertEqual(proof['status'],'MODERN_SIGNATURE_CF_BYTES_PRESERVED');self.assertFalse(proof['cryptographic_validation']);self.assertEqual(proof['bytes'],33)
    def test_explicit_mode_and_presence_required(self):
        with self.assertRaises(ValueError):signature_profile_guard(Source(),UID,{'xml_version':'2.21'})
        signature_profile_guard(Source(),UID,{'xml_version':'2.21'},modern_passthrough=True)
        with self.assertRaises(ValueError):signature_profile_guard(Source(),UID,{'xml_version':'2.20'},modern_passthrough=True)
        with self.assertRaises(ValueError):signature_profile_guard(Source(),'other-owner',{'xml_version':'2.21'},modern_passthrough=True)
    def test_proof_supplies_the_assembler_footer_validator_pin(self):
        proof=self.validate(Source())
        self.assertEqual(proof['fixed_profile_sha256'],hashlib.sha256(pathlib.Path(signature_rules.__file__).read_bytes()).hexdigest())
    def test_legacy_and_suppression_remain_refused(self):
        with self.assertRaises(ValueError):self.validate(Source(True))
        with self.assertRaises(ValueError):signature_profile_guard(Source(),UID,{'xml_version':'2.21'},legacy_flags=True,modern_passthrough=True)
    def test_payload_change_refused(self):
        with self.assertRaisesRegex(ValueError,'differs from CF bytes'):self.validate(Source(),mutation=lambda p:p.write_bytes(b'changed'))
    def test_duplicate_wrong_route_or_unsupported_record_refused(self):
        row={'logical_name':UID+'.10','disposition':'supported','outputs':['Ext/MobileClientSignature.bin']}
        for entries in ([row,row],[row|{'outputs':['Ext/Else.bin']}],[row|{'disposition':'opaque'}],[row|{'logical_name':'other.10'}]):
            with self.subTest(entries=entries),self.assertRaises(ValueError):self.validate(Source(),entries)

if __name__=='__main__':unittest.main()
