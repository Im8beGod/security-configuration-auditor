import { useMutation, useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { createReport, downloadReport, getReport, reportKey } from '../../shared/api/reports'
import { StatusBadge } from '../../shared/components/WorkflowUi'
import type { AuditStatus } from '../../shared/types/workflow'
import { errorMessage, formatDate } from '../../shared/workflowFormat'

const reportable=new Set<AuditStatus>(['completed','completed_with_unknowns','completed_with_errors'])
export function AuditReportPanel({auditId,auditStatus}:{auditId:string;auditStatus:AuditStatus}) {
  const [reportId,setReportId]=useState<string|null>(null)
  const create=useMutation({mutationFn:()=>createReport(auditId),onSuccess:report=>setReportId(report.report_id)})
  const report=useQuery({queryKey:reportKey(reportId??''),queryFn:()=>getReport(reportId!),enabled:Boolean(reportId),refetchInterval:query=>['pending','generating'].includes(query.state.data?.status??'')?3000:false})
  const download=useMutation({mutationFn:()=>downloadReport(reportId!),onSuccess:blob=>{const url=URL.createObjectURL(blob);const link=document.createElement('a');link.href=url;link.download=`audit-${auditId}.pdf`;link.click();URL.revokeObjectURL(url)}})
  if(!reportable.has(auditStatus)) return <section className="panel report-panel"><div><span className="eyebrow">PDF report</span><h2>Available after audit completion</h2></div><p className="quiet-state">Reports represent persisted completed audit truth and cannot be generated from an active or failed audit.</p></section>
  const current=report.data??create.data
  return <section className="panel report-panel"><div className="section-title"><div><span className="eyebrow">Immutable export</span><h2>Device compliance PDF</h2></div>{current&&<StatusBadge value={current.status}/>}</div>{!current&&<><p>Generate a server-authored PDF from this audit's persisted findings, evidence, coverage, and reviewed remediation.</p><button className="button-primary" disabled={create.isPending} onClick={()=>create.mutate()}>{create.isPending?'Queuing report...':'Generate PDF'}</button></>}{current&&['pending','generating'].includes(current.status)&&<p className="quiet-state">The report is {current.status}. This page checks for completion automatically.</p>}{current?.status==='ready'&&<div className="next-action"><div><strong>Report ready</strong><span>{current.byte_size?.toLocaleString()} bytes · generated {formatDate(current.generated_at)}</span></div><button className="button-primary" disabled={download.isPending} onClick={()=>download.mutate()}>{download.isPending?'Preparing...':'Download PDF'}</button></div>}{current?.status==='failed'&&<p className="error-message" role="alert">Report generation failed. {current.failure_message??'Try generating a new report.'}</p>}{(create.error||report.error||download.error)&&<p className="error-message" role="alert">{errorMessage(create.error??report.error??download.error)}</p>}</section>
}
