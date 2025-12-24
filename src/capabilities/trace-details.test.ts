import { getTraceDetails, findTraces } from './trace-details';
import { HttpClient } from '@dynatrace-sdk/http-client';
import { executeDql } from './execute-dql';

jest.mock('./execute-dql');

describe('getTraceDetails', () => {
  let mockHttpClient: jest.Mocked<HttpClient>;
  let mockExecuteDql: jest.MockedFunction<typeof executeDql>;

  beforeEach(() => {
    mockHttpClient = {} as jest.Mocked<HttpClient>;
    mockExecuteDql = executeDql as jest.MockedFunction<typeof executeDql>;
    jest.clearAllMocks();
  });

  it('should execute DQL query with trace ID', async () => {
    const traceId = 'test-trace-id-123';
    const mockResult = {
      records: [
        {
          'span.name': 'GET /api/users',
          'span.kind': 'SERVER',
          'span.status': 'OK',
          'service.name': 'user-service',
        },
      ],
      metadata: {},
    };
    mockExecuteDql.mockResolvedValue(mockResult);

    const result = await getTraceDetails(mockHttpClient, traceId);

    expect(mockExecuteDql).toHaveBeenCalledWith(mockHttpClient, {
      query: expect.stringContaining(`trace.id == "${traceId}"`),
      maxResultRecords: 5000,
      maxResultBytes: 5000000,
    });
    expect(result).toEqual(mockResult);
  });

  it('should use custom timeframe when provided', async () => {
    const traceId = 'test-trace-id-123';
    const mockResult = { records: [], metadata: {} };
    mockExecuteDql.mockResolvedValue(mockResult);

    await getTraceDetails(mockHttpClient, traceId, '6h');

    expect(mockExecuteDql).toHaveBeenCalledWith(
      mockHttpClient,
      expect.objectContaining({
        query: expect.stringContaining('from: now()-6h'),
      }),
    );
  });

  it('should fetch all span fields including HTTP and DB details', async () => {
    const traceId = 'test-trace-id-123';
    const mockResult = { records: [], metadata: {} };
    mockExecuteDql.mockResolvedValue(mockResult);

    await getTraceDetails(mockHttpClient, traceId);

    const call = mockExecuteDql.mock.calls[0][1];
    expect(call.query).toContain('http.method');
    expect(call.query).toContain('http.route');
    expect(call.query).toContain('db.system');
    expect(call.query).toContain('db.statement');
    expect(call.query).toContain('exception.type');
  });
});

describe('findTraces', () => {
  let mockHttpClient: jest.Mocked<HttpClient>;
  let mockExecuteDql: jest.MockedFunction<typeof executeDql>;

  beforeEach(() => {
    mockHttpClient = {} as jest.Mocked<HttpClient>;
    mockExecuteDql = executeDql as jest.MockedFunction<typeof executeDql>;
    jest.clearAllMocks();
  });

  it('should execute DQL query with default parameters', async () => {
    const mockResult = {
      records: [
        {
          'trace.id': 'trace-1',
          'span_count': 5,
          'error_count': 0,
          'trace_duration_ms': 150,
        },
      ],
      metadata: {},
    };
    mockExecuteDql.mockResolvedValue(mockResult);

    const result = await findTraces(mockHttpClient, {});

    expect(mockExecuteDql).toHaveBeenCalledWith(mockHttpClient, {
      query: expect.stringContaining('fetch spans'),
      maxResultRecords: 5000,
      maxResultBytes: 5000000,
    });
    expect(result).toEqual(mockResult);
  });

  it('should filter by service name when provided', async () => {
    const mockResult = { records: [], metadata: {} };
    mockExecuteDql.mockResolvedValue(mockResult);

    await findTraces(mockHttpClient, { serviceName: 'user-service' });

    expect(mockExecuteDql).toHaveBeenCalledWith(
      mockHttpClient,
      expect.objectContaining({
        query: expect.stringContaining('service.name == "user-service"'),
      }),
    );
  });

  it('should filter by service entity ID when provided', async () => {
    const mockResult = { records: [], metadata: {} };
    mockExecuteDql.mockResolvedValue(mockResult);

    await findTraces(mockHttpClient, { serviceEntityId: 'SERVICE-123' });

    expect(mockExecuteDql).toHaveBeenCalledWith(
      mockHttpClient,
      expect.objectContaining({
        query: expect.stringContaining('dt.entity.service == "SERVICE-123"'),
      }),
    );
  });

  it('should filter by error status when hasError is true', async () => {
    const mockResult = { records: [], metadata: {} };
    mockExecuteDql.mockResolvedValue(mockResult);

    await findTraces(mockHttpClient, { hasError: true });

    expect(mockExecuteDql).toHaveBeenCalledWith(
      mockHttpClient,
      expect.objectContaining({
        query: expect.stringContaining('span.status == "ERROR"'),
      }),
    );
  });

  it('should filter by operation name when provided', async () => {
    const mockResult = { records: [], metadata: {} };
    mockExecuteDql.mockResolvedValue(mockResult);

    await findTraces(mockHttpClient, { operationName: 'GET /api/users' });

    expect(mockExecuteDql).toHaveBeenCalledWith(
      mockHttpClient,
      expect.objectContaining({
        query: expect.stringContaining('span.name == "GET /api/users"'),
      }),
    );
  });

  it('should filter by minimum duration when provided', async () => {
    const mockResult = { records: [], metadata: {} };
    mockExecuteDql.mockResolvedValue(mockResult);

    await findTraces(mockHttpClient, { minDurationMs: 1000 });

    expect(mockExecuteDql).toHaveBeenCalledWith(
      mockHttpClient,
      expect.objectContaining({
        query: expect.stringContaining('trace_duration_ms >= 1000'),
      }),
    );
  });

  it('should use custom timeframe when provided', async () => {
    const mockResult = { records: [], metadata: {} };
    mockExecuteDql.mockResolvedValue(mockResult);

    await findTraces(mockHttpClient, { timeframe: '6h' });

    expect(mockExecuteDql).toHaveBeenCalledWith(
      mockHttpClient,
      expect.objectContaining({
        query: expect.stringContaining('from: now()-6h'),
      }),
    );
  });

  it('should limit results to maxTracesToDisplay', async () => {
    const mockResult = { records: [], metadata: {} };
    mockExecuteDql.mockResolvedValue(mockResult);

    await findTraces(mockHttpClient, { maxTracesToDisplay: 5 });

    expect(mockExecuteDql).toHaveBeenCalledWith(
      mockHttpClient,
      expect.objectContaining({
        query: expect.stringContaining('| limit 5'),
      }),
    );
  });

  it('should combine multiple filters with AND logic', async () => {
    const mockResult = { records: [], metadata: {} };
    mockExecuteDql.mockResolvedValue(mockResult);

    await findTraces(mockHttpClient, {
      serviceName: 'user-service',
      hasError: true,
      minDurationMs: 500,
    });

    const call = mockExecuteDql.mock.calls[0][1];
    expect(call.query).toContain('service.name == "user-service"');
    expect(call.query).toContain('span.status == "ERROR"');
    expect(call.query).toContain('trace_duration_ms >= 500');
  });
});
