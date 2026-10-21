import { NextResponse } from 'next/server';
import { ZodError, type ZodType } from 'zod';
import { ApiError } from './api-error';

const NO_STORE = { 'Cache-Control': 'no-store, max-age=0' } as const;

export function jsonOk<T>(data: T, status = 200): NextResponse {
  return NextResponse.json(data, { status, headers: NO_STORE });
}

export function jsonCreated<T>(data: T): NextResponse {
  return jsonOk(data, 201);
}

export function jsonError(error: ApiError): NextResponse {
  return NextResponse.json(
    {
      error: error.code,
      message: error.message,
      ...(error.details === undefined ? {} : { details: error.details }),
    },
    { status: error.status, headers: NO_STORE },
  );
}

export async function readJson<T>(req: Request, schema: ZodType<T>): Promise<T> {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    throw new ApiError(400, 'invalid_json', 'Request body must be valid JSON.');
  }

  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    throw new ApiError(400, 'validation_error', 'Request body is invalid.', {
      issues: parsed.error.issues.map((issue) => ({
        path: issue.path.join('.'),
        message: issue.message,
      })),
    });
  }
  return parsed.data;
}

export function handleRouteError(error: unknown): NextResponse {
  if (error instanceof ApiError) {
    return jsonError(error);
  }
  if (error instanceof ZodError) {
    return jsonError(
      new ApiError(400, 'validation_error', 'Request is invalid.', {
        issues: error.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
        })),
      }),
    );
  }

  console.error('[api] unhandled error:', error);
  return jsonError(
    new ApiError(500, 'internal_error', 'Something went wrong on the server.'),
  );
}

export function parseIntParam(
  raw: string | null,
  options: { min: number; max: number; fallback: number },
): number {
  if (raw === null || raw === '') return options.fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < options.min || value > options.max) {
    throw new ApiError(400, 'invalid_parameter', 'Numeric parameter is out of range.');
  }
  return value;
}
