import { NextRequest, NextResponse } from 'next/server';
import { analyzeWebsiteUrl } from '@/lib/pipeline';
import { z } from 'zod';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

const RequestSchema = z.object({
  url: z
    .string({ required_error: 'URL is required.' })
    .trim()
    .min(1, 'URL cannot be empty.')
    .max(2048, 'URL exceeds maximum allowable length of 2048 characters.')
});

export async function POST(req: NextRequest) {
  try {
    let body: unknown;
    try {
      body = await req.json();
    } catch {
      return NextResponse.json(
        {
          error: 'Invalid JSON request body. Expected {"url": "https://example.com"}',
          code: 'INVALID_JSON'
        },
        { status: 400 }
      );
    }

    const parseResult = RequestSchema.safeParse(body);
    if (!parseResult.success) {
      const issue = parseResult.error.issues[0]?.message || 'Invalid input parameter.';
      return NextResponse.json(
        {
          error: issue,
          code: 'VALIDATION_ERROR'
        },
        { status: 400 }
      );
    }

    const { url } = parseResult.data;

    try {
      const result = await analyzeWebsiteUrl(url);
      return NextResponse.json(result, {
        status: 200,
        headers: {
          'Cache-Control': 'no-store, max-age=0'
        }
      });
    } catch (analysisErr: unknown) {
      const error = analysisErr as Error;
      const isMalformed =
        error.message?.includes('Invalid') ||
        error.message?.includes('Malformed') ||
        error.message?.includes('domain name') ||
        error.message?.includes('Unsupported protocol');

      if (isMalformed) {
        return NextResponse.json(
          {
            error: error.message,
            code: 'MALFORMED_URL',
            recommendation: 'Please enter a valid website address, e.g. https://example.com'
          },
          { status: 400 }
        );
      }

      const isSecurityError =
        error.message?.includes('Security validation failed') ||
        error.message?.includes('Restricted') ||
        error.message?.includes('SSRF') ||
        error.message?.includes('private');

      if (isSecurityError) {
        return NextResponse.json(
          {
            error: error.message,
            code: 'SSRF_RESTRICTION',
            recommendation: 'Only public, routable internet websites can be submitted for analysis.'
          },
          { status: 400 }
        );
      }

      console.error('[API /api/analyze Error]', error);
      return NextResponse.json(
        {
          error: 'An unexpected error occurred during website analysis.',
          code: 'ANALYSIS_ERROR',
          details: error.message
        },
        { status: 500 }
      );
    }
  } catch (err: unknown) {
    const error = err as Error;
    console.error('[API Server Error]', error);
    return NextResponse.json(
      {
        error: 'Internal server error.',
        code: 'INTERNAL_ERROR'
      },
      { status: 500 }
    );
  }
}

export async function GET() {
  return NextResponse.json({
    service: 'ShopShield Scam Intelligence API',
    status: 'online',
    endpoint: 'POST /api/analyze',
    usage: {
      headers: { 'Content-Type': 'application/json' },
      body: { url: 'https://example-shop.com' }
    }
  });
}
