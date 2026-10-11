import http from 'k6/http';
import { check } from 'k6';
import { Counter, Trend } from 'k6/metrics';

const corpus = JSON.parse(open('/corpus/corpus.json'));
const acceptedLatency = new Trend('accepted_latency', true);
const rejected = new Counter('rejected_requests');
const rate = Number(__ENV.RATE || 2);
const duration = __ENV.DURATION || '30s';
const batchSize = Number(__ENV.BATCH_SIZE || 10);

export const options = {
  scenarios: { submit: { executor: 'constant-arrival-rate', rate, timeUnit: '1s', duration, preAllocatedVUs: 10, maxVUs: 50 } },
  thresholds: { http_req_failed: ['rate==0'] },
};

export default function () {
  const start = (__VU + __ITER) % corpus.length;
  const items = [];
  for (let i = 0; i < batchSize; i++) items.push(corpus[(start + i) % corpus.length].resource);
  const identity = `${__ENV.RUN_ID}-${__VU}-${__ITER}`;
  const body = JSON.stringify({ kind: 'manifest', target: `kalm/${identity}`, asset: `capacity/${__ENV.RUN_ID}`, series: 'manifest-throughput', manifest: { apiVersion: 'v1', kind: 'List', items } });
  const response = http.post(`${__ENV.BASE_URL}/api/v1/scans`, body, { headers: { Authorization: `Bearer ${__ENV.API_TOKEN}`, 'Content-Type': 'application/json', 'Idempotency-Key': identity }, timeout: '30s' });
  acceptedLatency.add(response.timings.duration);
  if (!check(response, { accepted: (r) => r.status === 202 })) rejected.add(1);
}

export function handleSummary(data) {
  return { '/results/k6-summary.json': JSON.stringify(data, null, 2) };
}
