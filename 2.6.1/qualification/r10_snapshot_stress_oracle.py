#!/usr/bin/env python3
from __future__ import annotations
import ast, hashlib, hmac, json, shutil, sys, tempfile
from pathlib import Path

MARKER='.mcp-task-workspace.json'

def strip_node(node):
    node=ast.fix_missing_locations(node)
    if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
        node.decorator_list=[]; node.returns=None
        for a in list(node.args.args)+list(node.args.kwonlyargs): a.annotation=None
        if node.args.vararg: node.args.vararg.annotation=None
        if node.args.kwarg: node.args.kwarg.annotation=None
    return node

def load_funcs(source: Path, root: Path, rows_holder: dict):
    tree=ast.parse(source.read_text(encoding='utf-8'))
    wanted={'_canonical_state_digest','_task_workspace_resource_rows','execution_snapshot'}
    nodes=[]; constants={}
    for n in tree.body:
        if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id.startswith('SNAPSHOT_'):
            try: constants[n.targets[0].id]=ast.literal_eval(n.value)
            except Exception: pass
        if isinstance(n,ast.FunctionDef) and n.name in wanted:
            nodes.append(strip_node(n))
    mod=ast.Module(body=nodes,type_ignores=[]); ast.fix_missing_locations(mod)
    def validate_output_limit(n):
        if not isinstance(n,int) or n<1000 or n>160000: raise ValueError('bad max')
    def enforce(value,max_bytes):
        validate_output_limit(max_bytes)
        size=len(json.dumps(value,ensure_ascii=False,separators=(',',':')).encode())
        if size>max_bytes: raise ValueError(f'Structured output exceeds max_bytes ({size} > {max_bytes}). Narrow the request.')
        return value
    def workspace_snapshot():
        return {'current_branch':'main','head':'1'*40,'origin_main':'1'*40,'ahead':0,'behind':0,'worktree_fingerprint':'2'*64,'index_fingerprint':'3'*64,'staged_files':[],'conflicted_files':[],'worktree_count':1,'stash_count':0,'active_git_operation':None}
    lease={'active':False,'lease_id':None,'execution_id':None,'authorization_digest':None,'baseline_head':None,'baseline_worktree_fingerprint':None,'status':'released','sequence':0,'executor_boot_id':'boot','provenance_label':None}
    ns={'json':json,'hmac':hmac,'hashlib':hashlib,'TASK_WORKSPACE_ROOT':root,'TASK_WORKSPACE_MARKER':MARKER,
        'validate_output_limit':validate_output_limit,'enforce_structured_output':enforce,'workspace_snapshot':workspace_snapshot,
        'read_active_lease_raw':lambda:None,'public_lease_view':lambda _x:dict(lease),'executor_recovery_status':lambda:{'mutation_safe':True,'incomplete_file_journals':[],'stale_or_owned_processes':[]},
        '_validation_state_rows':lambda:(None,[]),'_most_recent_mutation_receipts':lambda:[], '_public_local_process_rows':lambda:list(rows_holder['rows']),
        'sha256_text':lambda s:hashlib.sha256(s.encode()).hexdigest(),'EXECUTOR_VERSION':'2.6.1','source_sha256':lambda:'a'*64,'schema_contract_digest':lambda:'b'*64,
        'TOOLSET_REVISION':8,'EXECUTOR_BOOT_ID':'boot','WORKTREE_FINGERPRINT_REVISION':'2','WORKTREE_FINGERPRINT_SEMANTICS':'stable','INDEX_FINGERPRINT_REVISION':'1','INDEX_FINGERPRINT_SEMANTICS':'stable','now_iso':lambda:'2026-08-25T00:00:00+00:00'}
    ns.update(constants)
    exec(compile(mod,str(source),'exec'),ns)
    return ns

def make_workspace(root:Path,wid:str,created:str,label:str):
    d=root/wid; d.mkdir(parents=True,exist_ok=True); (d/MARKER).write_text(json.dumps({'workspace_id':wid,'created_at':created,'task_label':label}),encoding='utf-8')

def make_rows(root:Path):
    rows=[]; active='00000000-0000-4000-8000-000000000001'; make_workspace(root,active,'2026-08-25T00:00:00+00:00','active-oldest')
    exe='/bin/sleep-'+'x'*160
    for i in range(40): rows.append({'run_id':f'10000000-0000-4000-8000-{i:012d}','operation_id':f'20000000-0000-4000-8000-{i:012d}','workspace_id':active,'lease_id':None,'execution_id':None,'execution_class':'scratch','status':'completed','classification':'expected_exit','resolved_executable':exe,'started_at':'2026-08-25T00:00:00+00:00','completed_at':'2026-08-25T00:00:01+00:00','pid':None,'pgid':None})
    for wi in range(48):
        wid=f'30000000-0000-4000-8000-{wi:012d}'; make_workspace(root,wid,f'2026-08-25T00:{wi+1:02d}:00+00:00',f'idle-{wi}')
        for j in range(24):
            k=wi*24+j
            rows.append({'run_id':f'40000000-0000-4000-8000-{k:012d}','operation_id':f'50000000-0000-4000-8000-{k:012d}','workspace_id':wid,'lease_id':None,'execution_id':None,'execution_class':'scratch','status':'completed','classification':'expected_exit','resolved_executable':exe,'started_at':'2026-08-25T00:00:00+00:00','completed_at':'2026-08-25T00:00:01+00:00','pid':None,'pgid':None})
    running='60000000-0000-4000-8000-000000000001'
    runrow={'run_id':running,'operation_id':'70000000-0000-4000-8000-000000000001','workspace_id':active,'lease_id':None,'execution_id':None,'execution_class':'scratch','status':'running','classification':None,'resolved_executable':'/bin/sleep','started_at':'2026-08-25T00:00:00+00:00','completed_at':None,'pid':12345,'pgid':12345}
    return rows,active,running,runrow

def main():
    base=Path(tempfile.mkdtemp(prefix='r10-snapshot-oracle-',dir='output'))
    try:
        old_root=base/'old'; new_root=base/'new'; old_root.mkdir(); new_root.mkdir()
        old_holder={'rows':[]}; new_holder={'rows':[]}
        old=load_funcs(Path('output/candidate_final.py'),old_root,old_holder)
        new=load_funcs(Path('output/candidate_r10.py'),new_root,new_holder)
        baseline=new['execution_snapshot'](max_bytes=120000)
        terminal,active,running,runrow=make_rows(new_root); new_holder['rows']=terminal
        history=new['execution_snapshot'](max_bytes=120000)
        assert history['machine_state_digest']==baseline['machine_state_digest']
        assert history['continuation_digest']==baseline['continuation_digest']
        assert history['processes']['history_truncated'] is True and history['processes']['total_count']==1192
        assert history['task_workspace_presentation']['history_truncated'] is True and history['task_workspace_presentation']['total_count']==49
        new_holder['rows']=terminal+[runrow]
        snap=new['execution_snapshot'](max_bytes=120000)
        new_size=len(json.dumps(snap,ensure_ascii=False,separators=(',',':')).encode())
        assert new_size<=120000 and snap['cleanup_safe'] is False
        assert any(r.get('run_id')==running for r in snap['processes']['running'])
        assert any(r.get('run_id')==running for r in snap['processes']['owned'])
        ar=[w for w in snap['task_workspaces'] if w.get('workspace_id')==active]; assert len(ar)==1
        assert running in ar[0]['running_process_ids'] and running in ar[0]['owned_process_ids']
        assert ar[0]['owned_process_ids_truncated'] is True and ar[0]['owned_process_count']==41
        old_terminal,_,_,old_runrow=make_rows(old_root); old_holder['rows']=old_terminal+[old_runrow]
        old_failed=False; old_message=''
        try: old['execution_snapshot'](max_bytes=120000)
        except ValueError as exc: old_failed=True; old_message=str(exc)
        assert old_failed and 'Structured output exceeds max_bytes' in old_message
        print('r9_snapshot_overflow_reproduced=PASS')
        print('r10_snapshot_large_history_bounded=PASS')
        print('r10_running_evidence_preserved=PASS')
        print('r10_active_workspace_preserved=PASS')
        print('r10_digest_history_independence=PASS')
        print('r10_snapshot_serialized_bytes='+str(new_size))
        print('r10_process_total='+str(snap['processes']['total_count']))
        print('r10_process_returned='+str(snap['processes']['returned_count']))
        print('r10_workspace_total='+str(snap['task_workspace_presentation']['total_count']))
        print('r10_workspace_returned='+str(snap['task_workspace_presentation']['returned_count']))
    finally: shutil.rmtree(base,ignore_errors=True)
if __name__=='__main__': main()
