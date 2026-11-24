#!/usr/bin/env python3
"""Reproduce the pinned SDK overlay without mutating shared caches or module pins."""
# TRACEWEAVER: file-role=pinned-sdk-media-overlay; req=C-007; trace=TRACE-OWNERMSG-007; ver=VER-OWNERMSG-007
import argparse, hashlib, json, os, pathlib, re, shutil, subprocess, sys
ROOT=pathlib.Path(__file__).resolve().parent.parent
PIN='v0.0.0-20260925162019-b3832c2bd1d1'
ALLOW={'send.go','sendfb.go','socket/noisesocket.go','user.go','client.go','request.go','mediaconn.go'}
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def write_stable(path,text):
    if not path.exists() or path.read_text()!=text:
        temp=path.with_suffix(path.suffix+'.tmp-'+str(os.getpid()));temp.write_text(text);os.replace(temp,path)
def inventory(path):
    files={str(p.relative_to(path)):sha(p) for p in sorted(path.rglob('*')) if p.is_file()}
    return files,hashlib.sha256(''.join(k+'\0'+v+'\n' for k,v in sorted(files.items())).encode()).hexdigest()
# TRACEWEAVER: entrypoint=prepare; req=C-007; trace=TRACE-OWNERMSG-007; ver=VER-OWNERMSG-007
def prepare(output,manifest_path):
    output=output.resolve()
    if not output.is_relative_to(ROOT/'work'): raise ValueError('output must be inside project work/')
    manifest=json.loads(manifest_path.read_text())
    if manifest['module']!='go.mau.fi/whatsmeow' or manifest['version']!=PIN or set(manifest['files'])!=ALLOW: raise ValueError('unsupported module/version/path set')
    env=dict(os.environ,GOWORK='off',GOPROXY='off',GOSUMDB='off',GOTOOLCHAIN='local')
    module=json.loads(subprocess.check_output(['go','list','-m','-json','go.mau.fi/whatsmeow'],cwd=ROOT/'server',env=env))
    if module['Version']!=PIN or module.get('Replace'): raise ValueError('original module version/replacement mismatch')
    origin=pathlib.Path(module['Dir']).resolve()
    patch=ROOT/'server/sdkpatch/cancellable-send.patch'
    if sha(patch)!=manifest['patch_sha256']: raise ValueError('patch SHA mismatch')
    headers=re.findall(r'^(?:--- a/|\+\+\+ b/)([^\n]+)',patch.read_text(),re.M)
    if len(headers)!=2*len(ALLOW) or set(headers)!=ALLOW: raise ValueError('unexpected patch paths')
    for name,pins in manifest['files'].items():
        if sha(origin/name)!=pins['original_sha256']: raise ValueError('original SHA mismatch: '+name)
    originals,original_tree=inventory(origin)
    if original_tree!=manifest['upstream_tree_sha256']: raise ValueError('upstream snapshot tree SHA mismatch')
    output.mkdir(parents=True,exist_ok=True)
    upstream=output/'upstream'
    if upstream.exists():
        copied,tree=inventory(upstream)
        if copied!=originals: raise ValueError('task-local original snapshot was modified')
    else: shutil.copytree(origin,upstream)
    patched=output/'patched';patched.mkdir(exist_ok=True)
    # Apply only exact SHA-bound unified hunks against isolated writable copies.
    already_patched=all((patched/n).is_file() and sha(patched/n)==manifest['files'][n]['patched_sha256'] for n in ALLOW)
    if not already_patched:
        for name in ALLOW:
            dst=patched/name;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(origin/name,dst)
        subprocess.run(['patch','--batch','--fuzz=0','--forward','-p1','-d',str(patched),'-i',str(patch)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    replace={}
    for name,pins in manifest['files'].items():
        if sha(patched/name)!=pins['patched_sha256']: raise ValueError('patched SHA mismatch: '+name)
        replace[str(upstream/name)]=str(patched/name)
    overlay=output/'overlay.json';write_stable(overlay,json.dumps({'Replace':replace},indent=2)+'\n')
    tests=dict(replace)
    for target,fixture in [('whatsapp_connect_queue_test.go','serialization_test.go.txt'),('socket/whatsapp_connect_queue_test.go','socket_serialization_test.go.txt')]: tests[str(upstream/target)]=str(ROOT/'server/sdkpatch'/fixture)
    test_overlay=output/'test-overlay.json';write_stable(test_overlay,json.dumps({'Replace':tests},indent=2)+'\n')
    workspace=output/'go.work';write_stable(workspace,'go 1.27.0\nuse (\n'+str(ROOT/'server')+'\n'+str(upstream)+'\n)\n')
    receipt={'schema':'wc-sdk-overlay-receipt/1','module':module['Path'],'upstream_version':PIN,'workspace_metadata_limit':'SDK may report (devel); this receipt binds exact upstream version and source snapshot','original_dir':str(origin),'original_inventory':originals,'original_tree_sha256':original_tree,'manifest_sha256':sha(manifest_path),'patch_sha256':sha(patch),'patched_files':{n:sha(patched/n) for n in sorted(ALLOW)},'overlay_sha256':sha(overlay),'test_overlay_sha256':sha(test_overlay),'go_work_sha256':sha(workspace),'module_pins':{n:sha(ROOT/'server'/n) for n in ['go.mod','go.sum']},'test_fixtures':{n:sha(ROOT/'server/sdkpatch'/n) for n in ['serialization_test.go.txt','socket_serialization_test.go.txt']}}
    write_stable(output/'receipt.json',json.dumps(receipt,indent=2)+'\n')
    return output
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=pathlib.Path,default=ROOT/'work/whatsmeow-overlay');p.add_argument('--manifest',type=pathlib.Path,default=ROOT/'server/sdkpatch/manifest.json');args=p.parse_args()
    try: print(prepare(args.output,args.manifest))
    except (ValueError,KeyError,subprocess.SubprocessError,OSError) as e: print('SDK overlay refused: '+str(e),file=sys.stderr);sys.exit(1)
