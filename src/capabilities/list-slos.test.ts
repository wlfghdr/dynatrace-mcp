import { listSlos } from './list-slos';
import { HttpClient } from '@dynatrace-sdk/http-client';
import { executeDql } from './execute-dql';

jest.mock('./execute-dql');

describe('listSlos', () => {
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
          'slo.name': 'Test SLO',
          'slo.status': 'SUCCESS',
          'slo.sli_value': 99.5,
          'slo.target': 99.0,
          'slo.error_budget_remaining': 50,
          'slo.error_budget_consumed': 50,
        },
      ],
      metadata: {},
    };
    mockExecuteDql.mockResolvedValue(mockResult);

    const result = await listSlos(mockHttpClient);

    expect(mockExecuteDql).toHaveBeenCalledWith(mockHttpClient, {
      query: expect.stringContaining('fetch dt.davis.slo.status'),
      maxResultRecords: 5000,
      maxResultBytes: 5000000,
    });
    expect(result).toEqual(mockResult);
  });

  it('should filter by status when provided', async () => {
    const mockResult = { records: [], metadata: {} };
    mockExecuteDql.mockResolvedValue(mockResult);

    await listSlos(mockHttpClient, 'ERROR', '7d', undefined, 20);

    expect(mockExecuteDql).toHaveBeenCalledWith(
      mockHttpClient,
      expect.objectContaining({
        query: expect.stringContaining('| filter slo.status == "ERROR"'),
      }),
    );
  });

  it('should include additional filter when provided', async () => {
    const mockResult = { records: [], metadata: {} };
    mockExecuteDql.mockResolvedValue(mockResult);

    await listSlos(mockHttpClient, 'ALL', '7d', 'slo.related_entity == "SERVICE-123"', 20);

    expect(mockExecuteDql).toHaveBeenCalledWith(
      mockHttpClient,
      expect.objectContaining({
        query: expect.stringContaining('| filter slo.related_entity == "SERVICE-123"'),
      }),
    );
  });

  it('should use custom timeframe', async () => {
    const mockResult = { records: [], metadata: {} };
    mockExecuteDql.mockResolvedValue(mockResult);

    await listSlos(mockHttpClient, 'ALL', '30d', undefined, 20);

    expect(mockExecuteDql).toHaveBeenCalledWith(
      mockHttpClient,
      expect.objectContaining({
        query: expect.stringContaining('from: now()-30d'),
      }),
    );
  });

  it('should limit results to maxSlosToDisplay', async () => {
    const mockResult = { records: [], metadata: {} };
    mockExecuteDql.mockResolvedValue(mockResult);

    await listSlos(mockHttpClient, 'ALL', '7d', undefined, 10);

    expect(mockExecuteDql).toHaveBeenCalledWith(
      mockHttpClient,
      expect.objectContaining({
        query: expect.stringContaining('| limit 10'),
      }),
    );
  });
});
