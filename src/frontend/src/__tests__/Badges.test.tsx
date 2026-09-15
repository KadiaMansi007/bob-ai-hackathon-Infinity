import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SeverityBadge, ClassificationBadge, AgreementBadge, SourceBadge } from '../components/Badges'

describe('Badges', () => {
  it('renders CRITICAL severity badge', () => {
    render(<SeverityBadge severity="CRITICAL" />)
    expect(screen.getByText('CRITICAL')).toBeInTheDocument()
  })

  it('renders GENUINE_THREAT classification badge', () => {
    render(<ClassificationBadge classification="GENUINE_THREAT" />)
    expect(screen.getByText(/GENUINE THREAT/)).toBeInTheDocument()
  })

  it('renders FALSE_POSITIVE classification badge', () => {
    render(<ClassificationBadge classification="FALSE_POSITIVE" />)
    expect(screen.getByText(/FALSE POSITIVE/)).toBeInTheDocument()
  })

  it('renders AGREES agreement badge', () => {
    render(<AgreementBadge status="AGREES" />)
    expect(screen.getByText(/AGREES/)).toBeInTheDocument()
  })

  it('renders DISAGREES agreement badge', () => {
    render(<AgreementBadge status="DISAGREES" />)
    expect(screen.getByText(/DISAGREES/)).toBeInTheDocument()
  })

  it('renders SIEM source badge', () => {
    render(<SourceBadge sourceType="SIEM" />)
    expect(screen.getByText('SIEM')).toBeInTheDocument()
  })
})
