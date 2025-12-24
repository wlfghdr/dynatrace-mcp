import { HttpClient } from '@dynatrace-sdk/http-client';
import { executeDql } from './execute-dql';

/**
 * List Service Level Objectives (SLOs) from dt.davis.slo.status
 * @param dtClient Dynatrace HTTP Client
 * @param status Filter by SLO status (WARNING, ERROR, SUCCESS, ALL)
 * @param timeframe Timeframe to evaluate SLOs (e.g., '7d', '30d'). Default: '7d'
 * @param additionalFilter Optional additional DQL filter
 * @param maxSlosToDisplay Maximum number of SLOs to return
 * @returns DQL query result
 */
export const listSlos = async (
  dtClient: HttpClient,
  status: string = 'ALL',
  timeframe: string = '7d',
  additionalFilter?: string,
  maxSlosToDisplay: number = 20,
) => {
  // Build status filter
  let statusFilter = '';
  if (status !== 'ALL') {
    statusFilter = `| filter slo.status == "${status}"`;
  }

  // DQL Statement to fetch SLO status information
  const dql = `fetch dt.davis.slo.status, from: now()-${timeframe}, to: now()
${statusFilter}
${additionalFilter ? `| filter ${additionalFilter}` : ''}
| fields slo.name, slo.status, slo.sli_value, slo.target, slo.error_budget_remaining, slo.error_budget_consumed, slo.related_entity
| sort slo.status desc, slo.error_budget_remaining asc
| limit ${maxSlosToDisplay}
`;

  return await executeDql(dtClient, { query: dql, maxResultRecords: 5000, maxResultBytes: 5000000 });
};
