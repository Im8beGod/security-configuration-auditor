const labels: Record<string, string> = {
  pass: 'Pass', fail: 'Fail', unknown: 'Unknown', manual_review: 'Manual review',
  not_applicable: 'Not applicable', process_error: 'Process error',
  missing_evidence: 'Missing evidence', unresolved_default: 'Unresolved default',
  conflicting_evidence: 'Conflicting evidence', unsupported_profile: 'Unsupported profile',
}

export const readable = (value: string) => labels[value] ?? value.replaceAll('_', ' ')
