import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import Layout from '../components/Layout'

describe('Layout', () => {
  it('renders navigation links', () => {
    render(
      <MemoryRouter>
        <Layout><div data-testid="child">child</div></Layout>
      </MemoryRouter>
    )
    expect(screen.getByText('Dashboard')).toBeInTheDocument()
    expect(screen.getByText('Alert Feed')).toBeInTheDocument()
    expect(screen.getByText('Incidents')).toBeInTheDocument()
    expect(screen.getByTestId('child')).toBeInTheDocument()
  })
})
