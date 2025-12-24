import { HttpClient } from '@dynatrace-sdk/http-client';
import { executeDql } from './execute-dql';

/**
 * Get detailed information about a specific trace by trace ID
 * @param dtClient Dynatrace HTTP Client
 * @param traceId The W3C trace ID or Dynatrace PurePath ID
 * @param timeframe Timeframe to search for the trace (e.g., '2h', '24h'). Default: '2h'
 * @returns DQL query result with all spans belonging to the trace
 */
export const getTraceDetails = async (dtClient: HttpClient, traceId: string, timeframe: string = '2h') => {
  // DQL Statement to fetch all spans for a specific trace ID
  const dql = `fetch spans, from: now()-${timeframe}, to: now()
| filter trace.id == "${traceId}"
| fields span.name, span.kind, span.status, span.start_time, span.end_time, 
         duration = (span.end_time - span.start_time) / 1000000, // Convert to milliseconds
         service.name, dt.entity.service,
         http.method, http.route, http.status_code, http.url,
         db.system, db.name, db.statement,
         exception.type, exception.message, exception.stacktrace,
         span.parent_id, span.id
| sort span.start_time asc
`;

  return await executeDql(dtClient, { query: dql, maxResultRecords: 5000, maxResultBytes: 5000000 });
};

/**
 * Find traces based on various criteria
 * @param dtClient Dynatrace HTTP Client
 * @param params Search parameters including serviceName, serviceEntityId, minDurationMs, hasError, operationName, timeframe
 * @returns DQL query result with trace summaries
 */
export const findTraces = async (
  dtClient: HttpClient,
  params: {
    serviceName?: string;
    serviceEntityId?: string;
    minDurationMs?: number;
    hasError?: boolean;
    operationName?: string;
    timeframe?: string;
    maxTracesToDisplay?: number;
  },
) => {
  const {
    serviceName,
    serviceEntityId,
    minDurationMs,
    hasError,
    operationName,
    timeframe = '1h',
    maxTracesToDisplay = 20,
  } = params;

  // Build filters based on provided parameters
  const filters: string[] = [];

  if (serviceName) {
    filters.push(`service.name == "${serviceName}"`);
  }

  if (serviceEntityId) {
    filters.push(`dt.entity.service == "${serviceEntityId}"`);
  }

  if (operationName) {
    filters.push(`span.name == "${operationName}"`);
  }

  if (hasError !== undefined && hasError) {
    filters.push(`span.status == "ERROR"`);
  }

  const filterClause = filters.length > 0 ? `| filter ${filters.join(' AND ')}` : '';

  // DQL Statement to find traces and aggregate span information
  const dql = `fetch spans, from: now()-${timeframe}, to: now()
${filterClause}
| summarize {
    span_count = count(),
    error_count = countIf(span.status == "ERROR"),
    min_start_time = min(span.start_time),
    max_end_time = max(span.end_time),
    services = collectDistinct(service.name),
    root_span_name = takeFirst(span.name)
  }, by: { trace.id }
| fieldsAdd trace_duration_ms = (max_end_time - min_start_time) / 1000000
${minDurationMs !== undefined ? `| filter trace_duration_ms >= ${minDurationMs}` : ''}
| sort trace_duration_ms desc
| limit ${maxTracesToDisplay}
`;

  return await executeDql(dtClient, { query: dql, maxResultRecords: 5000, maxResultBytes: 5000000 });
};
