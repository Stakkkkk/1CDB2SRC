"""Bind containerd manifest IDs and classic Docker config IDs to one shipped OCI image."""
import hashlib,json,re,tarfile
from ..util import require,fact

def identities(archive,runtime):
    require(fact(archive)==runtime['archive'],'Bundled runtime archive mismatch')
    with tarfile.open(archive,'r:') as tar:
        def document(descriptor):
            digest=descriptor['digest']
            require(re.fullmatch(r'sha256:[0-9a-f]{64}',digest) is not None,'Invalid OCI identity')
            member=tar.getmember('blobs/sha256/'+digest[7:])
            require(member.isfile() and member.size==descriptor['size'] and member.size<=1024**2,'Invalid OCI identity blob size')
            raw=tar.extractfile(member).read()
            require('sha256:'+hashlib.sha256(raw).hexdigest()==digest,'OCI identity digest mismatch')
            return json.loads(raw)
        index=json.load(tar.extractfile('index.json'))
        require(index['schemaVersion']==2 and len(index['manifests'])==1,'Unexpected OCI archive index')
        root=index['manifests'][0]
        require(root['digest']==runtime.get('provenance_image_id',runtime['image_id']),'OCI root differs from pinned runtime')
        image_index=document(root)
        rows=[row for row in image_index['manifests'] if row.get('platform')=={'architecture':'amd64','os':'linux'}]
        require(len(rows)==1,'Expected one Linux amd64 OCI image')
        image=document(rows[0]);config=document(image['config'])
        require(config['architecture']=='amd64' and config['os']=='linux','OCI config platform mismatch')
        return {'provenance_image_id':root['digest'],'platform_manifest_id':rows[0]['digest'],
                'classic_config_image_id':image['config']['digest'],'allowed_image_ids':[root['digest'],image['config']['digest']],
                'rootfs_diff_ids':config['rootfs']['diff_ids']}
