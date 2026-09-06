import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState, type ChangeEvent } from 'react'
import { Link } from 'react-router-dom'

import { bulkUpload } from '../../shared/api/workflow'
import { StatusBadge } from '../../shared/components/WorkflowUi'
import { errorMessage } from '../../shared/workflowFormat'
import type { BulkUploadResponse } from '../../shared/types/workflow'

export function UploadsPage() {
  const queryClient = useQueryClient()
  const [files, setFiles] = useState<File[]>([])
  const [result, setResult] = useState<BulkUploadResponse | null>(null)
  const upload = useMutation({ mutationFn: bulkUpload, onSuccess: (data) => { setResult(data); void queryClient.invalidateQueries({ queryKey: ['artifacts'] }) } })

  function selectFiles(event: ChangeEvent<HTMLInputElement>) {
    setFiles(Array.from(event.target.files ?? [])); setResult(null); upload.reset()
  }

  return <section className="page-stack">
    <header className="page-heading"><div><span className="eyebrow">Step 1</span><h1>Upload evidence</h1></div><p>Add configuration files or structured exports. Unknown vendor syntax is accepted when the file is safe text.</p></header>
    <div className="panel upload-panel">
      <label className="file-drop" htmlFor="evidence-files"><strong>Choose evidence files</strong><span>UTF-8 text, JSON, or XML. Up to 20 files, 10 MiB each.</span><input id="evidence-files" type="file" multiple onChange={selectFiles} /></label>
      {files.length > 0 ? <div><div className="section-title"><h2>Ready to upload</h2><span>{files.length} files</span></div><ul className="compact-list">{files.map((file) => <li key={`${file.name}-${file.lastModified}`}><span>{file.name}</span><small>{Math.max(1, Math.ceil(file.size / 1024))} KB</small></li>)}</ul><div className="button-row"><button className="button-primary" type="button" disabled={upload.isPending} onClick={() => upload.mutate(files)}>{upload.isPending ? 'Uploading evidence...' : 'Upload selected files'}</button><button className="button-quiet" type="button" disabled={upload.isPending} onClick={() => setFiles([])}>Clear</button></div></div> : <p className="quiet-state">Select one or more files to begin.</p>}
      {upload.isError && <p className="error-message" role="alert">{errorMessage(upload.error)}</p>}
    </div>
    {result && <section className="panel" aria-live="polite"><div className="section-title"><h2>Upload results</h2><strong>{result.succeeded} accepted · {result.failed} rejected</strong></div><div className="result-grid">{result.results.map((item, index) => <article className="result-card" key={`${item.filename}-${index}`}><div><strong>{item.filename}</strong><StatusBadge value={item.status} /></div>{item.status === 'success' ? <dl className="mini-details"><div><dt>Family</dt><dd>{item.artifact.content_family}</dd></div><div><dt>Evidence</dt><dd>{item.artifact.evidence_type.replaceAll('_', ' ')}</dd></div><div><dt>State</dt><dd>{item.artifact.status}</dd></div></dl> : <p className="error-message">{item.error.message}</p>}</article>)}</div>{result.succeeded > 0 && <div className="next-action"><div><strong>Evidence is ready to organize</strong><span>Create or choose a Device, then build an evidence snapshot.</span></div><Link className="button-primary" to="/devices">Continue to Devices</Link></div>}</section>}
  </section>
}
