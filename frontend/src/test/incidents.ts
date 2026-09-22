import type { EntityGraph, Evidence, IncidentDetail, Me, Note, Timeline } from "@/api/types";

import { adminMe } from "./utils";

export const INCIDENT_ID = "0199a000-0000-7000-8000-000000000001";
const BURST_LINK = "0199a000-0000-7000-8000-00000000000a";
const LOGON_LINK = "0199a000-0000-7000-8000-00000000000b";
const PS_LINK = "0199a000-0000-7000-8000-00000000000c";

export const analystMe: Me = {
  ...adminMe,
  id: "u-analyst",
  email: "analyst@example.com",
  full_name: "Sam Analyst",
  roles: ["analyst"],
  permissions: ["event:read", "finding:read", "incident:read", "incident:update", "platform:read"],
};

export const seniorMe: Me = {
  ...analystMe,
  id: "u-senior",
  roles: ["senior_analyst"],
  permissions: [...analystMe.permissions, "incident:resolve"],
};

const times = { created_at: "2026-09-15T09:40:30Z", updated_at: "2026-09-15T09:48:00Z" };

export const incidentDetail: IncidentDetail = {
  id: INCIDENT_ID,
  title: "Successful logon after repeated failures from 198.51.100.23, then execution on ws-fin-07",
  severity_id: 5,
  severity: "Critical",
  status: "new",
  resolution: null,
  techniques: ["T1059.001", "T1110.001"],
  tactics: ["credential_access", "execution"],
  finding_count: 2,
  event_count: 7,
  first_seen: "2026-09-15T09:40:11Z",
  last_seen: "2026-09-15T09:42:37Z",
  closed_at: null,
  version: 2,
  ...times,
  assessment: [
    {
      rule: "credential-compromise",
      severity_id: 4,
      because: "a successful logon followed brute-force failures from the same source",
      links: [LOGON_LINK],
    },
  ],
  links: [
    {
      id: BURST_LINK,
      kind: "finding",
      rule: "opened",
      reason: "no open incident shares an entity with this finding within the correlation window",
      finding_id: "f-burst",
      event_uid: null,
      evidence: ["e-fail-1", "e-fail-2", "e-fail-3", "e-fail-4", "e-fail-5"],
      matched: [],
      detail: { rule_title: "Burst of authentication failures for one account from one source" },
      first_seen: "2026-09-15T09:40:11Z",
      last_seen: "2026-09-15T09:40:21Z",
      created_at: times.created_at,
    },
    {
      id: LOGON_LINK,
      kind: "event",
      rule: "auth-success-after-failures",
      reason:
        "successful logon as acme\\jsmith from 198.51.100.23 to ws-fin-07 after 1 brute-force finding(s)",
      finding_id: null,
      event_uid: "e-logon",
      evidence: ["e-logon"],
      matched: [{ key: "ip:198.51.100.23", incident_events: ["e-fail-1"], new_events: ["e-logon"] }],
      detail: {},
      first_seen: "2026-09-15T09:41:02Z",
      last_seen: "2026-09-15T09:41:02Z",
      created_at: times.created_at,
    },
    {
      id: PS_LINK,
      kind: "finding",
      rule: "shared-entity",
      reason: "shares host:ws-fin-07, user:acme\\jsmith with the incident, within 2h of its activity",
      finding_id: "f-ps",
      event_uid: null,
      evidence: ["e-ps"],
      matched: [{ key: "host:ws-fin-07", incident_events: ["e-fail-1"], new_events: ["e-ps"] }],
      detail: {
        rule_title: "PowerShell started with an encoded command",
        rule_author: "Florian Roth (Nextron Systems)",
        rule_source: "https://github.com/SigmaHQ/sigma/blob/r2026-07-01/rules/windows/x.yml",
      },
      first_seen: "2026-09-15T09:42:37Z",
      last_seen: "2026-09-15T09:42:37Z",
      created_at: times.created_at,
    },
  ],
  entities: [
    {
      key: "host:ws-fin-07",
      type: "host",
      value: "ws-fin-07",
      links: true,
      first_seen: "2026-09-15T09:40:11Z",
      last_seen: "2026-09-15T09:42:37Z",
      events: ["e-fail-1", "e-logon", "e-ps"],
    },
  ],
};

export const timeline: Timeline = {
  unresolved_events: [],
  steps: [
    {
      id: "e-fail-1",
      first_seen: "2026-09-15T09:40:11Z",
      last_seen: "2026-09-15T09:40:21Z",
      action: "Failed logon",
      outcome: "failure",
      host: "ws-fin-07",
      users: ["acme\\jsmith"],
      process: null,
      parent_process: null,
      command_lines: [],
      remote: "198.51.100.23",
      remote_ports: [],
      domains: [],
      citations: [
        {
          link_id: BURST_LINK,
          rule: "opened",
          title: "Burst of authentication failures for one account from one source",
          techniques: ["T1110.001"],
        },
      ],
      events: ["e-fail-1", "e-fail-2", "e-fail-3", "e-fail-4", "e-fail-5"],
      entities: ["host:ws-fin-07", "ip:198.51.100.23", "user:acme\\jsmith"],
    },
    {
      id: "e-logon",
      first_seen: "2026-09-15T09:41:02Z",
      last_seen: "2026-09-15T09:41:02Z",
      action: "Logged on",
      outcome: "success",
      host: "ws-fin-07",
      users: ["acme\\jsmith"],
      process: null,
      parent_process: null,
      command_lines: [],
      remote: "198.51.100.23",
      remote_ports: [],
      domains: [],
      citations: [{ link_id: LOGON_LINK, rule: "auth-success-after-failures", title: "…", techniques: [] }],
      events: ["e-logon"],
      entities: ["host:ws-fin-07", "ip:198.51.100.23", "user:acme\\jsmith"],
    },
    {
      id: "e-ps",
      first_seen: "2026-09-15T09:42:37Z",
      last_seen: "2026-09-15T09:42:37Z",
      action: "Process started",
      outcome: "success",
      host: "ws-fin-07",
      users: ["acme\\jsmith"],
      process: "powershell.exe",
      parent_process: "explorer.exe",
      command_lines: ["powershell.exe -NoProfile -EncodedCommand SQBFAFgA"],
      remote: null,
      remote_ports: [],
      domains: [],
      citations: [
        {
          link_id: PS_LINK,
          rule: "shared-entity",
          title: "PowerShell started with an encoded command",
          techniques: ["T1059.001"],
        },
      ],
      events: ["e-ps"],
      entities: ["host:ws-fin-07", "user:acme\\jsmith", "process:powershell.exe"],
    },
  ],
};

function failure(uid: string, second: number) {
  return {
    event_uid: uid,
    time: `2026-09-15T09:40:${String(second).padStart(2, "0")}Z`,
    class_uid: 3002,
    activity_id: 1,
    status_id: 2,
    action: "Failed logon",
    outcome: "failure",
    message: "An account failed to log on",
    raw: null,
    roles: { host: ["host:ws-fin-07"], src_ip: ["ip:198.51.100.23"], user: ["user:acme\\jsmith"] },
    detail: {},
    cited_by: [BURST_LINK],
  };
}

export const evidence: Evidence = {
  unresolved_events: [],
  events: [
    failure("e-fail-1", 11),
    failure("e-fail-2", 13),
    failure("e-fail-3", 16),
    failure("e-fail-4", 19),
    failure("e-fail-5", 21),
    {
      event_uid: "e-logon",
      time: "2026-09-15T09:41:02Z",
      class_uid: 3002,
      activity_id: 1,
      status_id: 1,
      action: "Logged on",
      outcome: "success",
      message: "An account was successfully logged on",
      raw: '{"EventID":4624,"LogonType":"10","IpAddress":"198.51.100.23"}',
      roles: { host: ["host:ws-fin-07"], src_ip: ["ip:198.51.100.23"], user: ["user:acme\\jsmith"] },
      detail: { logon_type_id: 10 },
      cited_by: [LOGON_LINK],
    },
    {
      event_uid: "e-ps",
      time: "2026-09-15T09:42:37Z",
      class_uid: 1007,
      activity_id: 1,
      status_id: 1,
      action: "Process started",
      outcome: "success",
      message: "A new process has been created",
      raw: null,
      roles: {
        host: ["host:ws-fin-07"],
        user: ["user:acme\\jsmith"],
        process: ["process:powershell.exe"],
        parent_process: ["process:explorer.exe"],
      },
      detail: { cmd_line: "powershell.exe -NoProfile -EncodedCommand SQBFAFgA" },
      cited_by: [PS_LINK],
    },
  ],
};

export const graph: EntityGraph = {
  nodes: [
    {
      key: "ip:198.51.100.23",
      type: "ip",
      value: "198.51.100.23",
      external: true,
      first_seen: "2026-09-15T09:40:11Z",
      last_seen: "2026-09-15T09:41:02Z",
      event_count: 6,
      events: ["e-fail-1", "e-fail-2", "e-fail-3", "e-fail-4", "e-fail-5", "e-logon"],
    },
    {
      key: "host:ws-fin-07",
      type: "host",
      value: "ws-fin-07",
      external: false,
      first_seen: "2026-09-15T09:40:11Z",
      last_seen: "2026-09-15T09:42:37Z",
      event_count: 7,
      events: ["e-fail-1", "e-fail-2", "e-fail-3", "e-fail-4", "e-fail-5", "e-logon", "e-ps"],
    },
  ],
  edges: [
    {
      id: "ip:198.51.100.23|failed_logon|host:ws-fin-07",
      source: "ip:198.51.100.23",
      target: "host:ws-fin-07",
      relation: "failed_logon",
      label: "failed logon to",
      first_seen: "2026-09-15T09:40:11Z",
      last_seen: "2026-09-15T09:40:21Z",
      event_count: 5,
      events: ["e-fail-1", "e-fail-2", "e-fail-3", "e-fail-4", "e-fail-5"],
      detail: {},
    },
    {
      id: "ip:198.51.100.23|logon|host:ws-fin-07",
      source: "ip:198.51.100.23",
      target: "host:ws-fin-07",
      relation: "logon",
      label: "logged on to",
      first_seen: "2026-09-15T09:41:02Z",
      last_seen: "2026-09-15T09:41:02Z",
      event_count: 1,
      events: ["e-logon"],
      detail: {},
    },
  ],
};

export const note: Note = {
  id: "n-1",
  author_id: "u-analyst",
  author_email: "analyst@example.com",
  body: "RDP right after the burst.",
  created_at: "2026-09-15T10:00:00Z",
};
