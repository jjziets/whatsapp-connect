#!/usr/bin/env python3
"""Focused fail-closed packaging checks; real generator and pristine cache reads."""
import importlib.util,json,pathlib,tempfile,unittest,sys,subprocess
sys.dont_write_bytecode=True
from unittest import mock
ROOT=pathlib.Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('overlay',ROOT/'scripts/prepare-whatsmeow-overlay.py');overlay=importlib.util.module_from_spec(spec);spec.loader.exec_module(overlay)
class OverlayPins(unittest.TestCase):
 def test_rejects_wrong_version_original_patch_and_patched_hash(self):
  original=json.loads((ROOT/'server/sdkpatch/manifest.json').read_text())
  for kind in ['version','original','patch','patched']:
   with self.subTest(kind=kind),tempfile.TemporaryDirectory(dir=ROOT/'work') as tmp:
    data=json.loads(json.dumps(original))
    if kind=='version':data['version']='v0.0.0-wrong'
    elif kind=='patch':data['patch_sha256']='0'*64
    else:data['files']['send.go'][kind+'_sha256']='0'*64
    path=pathlib.Path(tmp)/'manifest.json';path.write_text(json.dumps(data))
    with self.assertRaises(ValueError):overlay.prepare(pathlib.Path(tmp)/'out',path)
    self.assertFalse((pathlib.Path(tmp)/'out/receipt.json').exists())
 def test_rejects_wrong_resolved_module(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'work') as tmp,mock.patch.object(overlay.subprocess,'check_output',return_value=b'{"Version":"v-wrong"}'):
   with self.assertRaises(ValueError):overlay.prepare(pathlib.Path(tmp)/'out',ROOT/'server/sdkpatch/manifest.json')
class WrapperOverrideGuard(unittest.TestCase):
 def test_actual_wrapper_rejects_overlay_spellings(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'work') as tmp:
   overlay_path=pathlib.Path(tmp)/'unreviewed.json';overlay_path.write_text('{"Replace":{}}')
   for spelling in ['--overlay=','--overlay','-overlay=','-overlay']:
    with self.subTest(spelling=spelling):
     args=[spelling+str(overlay_path)] if spelling.endswith('=') else [spelling,str(overlay_path)]
     result=subprocess.run([str(ROOT/'scripts/build-server.sh'),'build',*args,'-o',str(pathlib.Path(tmp)/'unexpected-binary')],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
     self.assertEqual(result.returncode,2,'wrapper did not refuse override: '+result.stderr)
     self.assertIn('Refusing externally supplied overlay',result.stderr)
     self.assertFalse((pathlib.Path(tmp)/'unexpected-binary').exists())
if __name__=='__main__':unittest.main()
