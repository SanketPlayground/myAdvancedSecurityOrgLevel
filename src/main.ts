import * as core from '@actions/core';
import * as xlsx from 'xlsx';
import { Octokit } from '@octokit/rest';
import { graphql } from '@octokit/graphql';
import * as fs from 'fs';

async function run(): Promise<void> {
  try {
    const token = core.getInput('token');
    if (!token) {
      core.error('Please set the INPUT_TOKEN env variable');
      return;
    }

    const octokit = new Octokit({ auth: token });

    const org = core.getInput('organization');
    if (!org) {
      core.error('Please provide the organization name');
      return;
    }

    const repos = await getOrganizationRepos(octokit, org);
    if (!repos || repos.length === 0) {
      core.error(`No repositories found in organization ${org}`);
      return;
    }

    console.log('Repositories in organization:', repos);

    const allData: { [key: string]: RepositoryData } = {};
    for (const repo of repos) {
      const [login, repoName] = repo.split('/');
      const dgIssues = await getDependabotReport(login, repoName, token);
      const csIssues = await getCodeScanningReport(login, repoName, octokit);
      const dgInfo = await getDependencyGraphReport(login, repoName, token);
      const secretScanningAlerts = await getSecretScanningReport(octokit, login, repoName);

      allData[repo] = {
        dgIssues,
        csIssues,
        dgInfo,
        secretScanningAlerts,
      };
    }

    await createExcel(allData);
  } catch (error) {
    if (error instanceof Error) core.setFailed(error.message);
  }
}

interface RepositoryData {
  dgIssues: string[][];
  csIssues: string[][];
  dgInfo: string[][];
  secretScanningAlerts: string[][];
}

async function getOrganizationRepos(octokit: Octokit, org: string): Promise<string[]> {
  const response = await octokit.paginate(octokit.rest.repos.listForOrg, {
    org,
  });
  return response.map((repo: any) => repo.full_name);
}

async function getSecretScanningReport(
  octokit: Octokit,
  login: string,
  repoName: string
): Promise<string[][]> {
  const csvData: string[][] = [];

  try {
    const secretScanningAlerts = await octokit.paginate(
      octokit.rest.secretScanning.listAlertsForRepo,
      {
        owner: login,
        repo: repoName
      }
    );

    const header: string[] = [
      'html_url',
      'secret_type',
      'secret',
      'state',
      'resolution'
    ];

    csvData.push(header);
    for (const alert of secretScanningAlerts) {
      const row: string[] = [
        alert.html_url!,
        alert.secret_type!,
        alert.secret!,
        alert.state!,
        alert.resolution!
      ];
      csvData.push(row);
    }
    return csvData;
  } catch (error) {
    if (error instanceof Error) {
      core.error(error.message);
      csvData.push([error.message, '', '', '', '']);
    }
    return csvData;
  }
}

async function getCodeScanningReport(
  login: string,
  repoName: string,
  octokit: Octokit
): Promise<string[][]> {
  const data = await octokit.paginate(octokit.rest.codeScanning.listAlertsForRepo, {
    owner: login,
    repo: repoName
  });

  const csvData: string[][] = [];
  const header: string[] = [
    'toolName',
    'toolVersion',
    'alertNumber',
    'htmlUrl',
    'state',
    'rule',
    'cwe',
    'severity',
    'location',
    'start-line',
    'end-line',
    'createdAt',
    'updatedAt',
    'fixedAt',
    'dismissedAt',
    'dismissedBy'
  ];

  csvData.push(header);
  for (const alert of data) {
    const rule: any = alert.rule;
    let securitySeverity = '';
    let securityCwe = '';
    if (rule.security_severity_level) {
      securitySeverity = rule.security_severity_level;
    } else {
      securitySeverity = rule.severity;
    }
    for (const cwe of rule.tags) {
      if (cwe.includes('external/cwe/cwe')) {
        securityCwe = `${securityCwe}${cwe}, `;
      }
    }
    securityCwe = securityCwe.replace(/,\s*$/, '');
    const _alert: any = alert;
    const row: string[] = [
      alert.tool.name!,
      alert.tool.version!,
      alert.number.toString(),
      alert.html_url,
      alert.state,
      rule.id,
      securityCwe,
      securitySeverity,
      alert.most_recent_instance.location!.path,
      alert.most_recent_instance.location!.start_line,
      alert.most_recent_instance.location!.end_line,
      alert.created_at,
      _alert.updated_at,
      _alert.fixed_at,
      alert.dismissed_at,
      alert.dismissed_by
    ];
    csvData.push(row);
  }

  return csvData;
}

async function getDependencyGraphReport(
  login: string,
  repoName: string,
  token: string
): Promise<string[][]> {
  const { repository } = await graphql(
    `
      {
        repository(owner: "${login}", name: "${repoName}") {
          name
          licenseInfo {
            name
          }
          dependencyGraphManifests {
            totalCount
            edges {
              node {
                filename
                dependencies {
                  edges {
                    node {
                      packageName
                      packageManager
                      requirements
                      repository {
                        licenseInfo {
                          name
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    `,
    {
      headers: {
        authorization: `token ${token}`,
        accept: 'application/vnd.github.hawkgirl-preview+json'
      }
    }
  );

  const csvData: string[][] = [];
  const header: string[] = [
    'manifest',
    'packageName',
    'packageManager',
    'requirements',
    'licenseInfo'
  ];

  csvData.push(header);
  for (const dependency of repository.dependencyGraphManifests.edges) {
    for (const dependencyEdge of dependency.node.dependencies.edges) {
      let licenseInfo = '';
      if (
        dependencyEdge.node &&
        dependencyEdge.node.repository &&
        dependencyEdge.node.repository.licenseInfo
      ) {
        licenseInfo = dependencyEdge.node.repository.licenseInfo.name;
      }
      const row: string[] = [
        dependency.node.filename,
        dependencyEdge.node.packageName,
        dependencyEdge.node.packageManager,
        dependencyEdge.node.requirements,
        licenseInfo
      ];
      csvData.push(row);
    }
  }
  return csvData;
}

async function getDependabotReport(
  login: string,
  repoName: string,
  token: string
): Promise<string[][]> {
  const csvData: string[][] = [];
  const header: string[] = [
    'ghsaId',
    'packageName',
    'packageManager',
    'severity',
    'firstPatchedVersion',
    'description'
  ];
  csvData.push(header);

  try {
    let response;
    let after = '';
    do {
      response = await fetchAPIResults(login, repoName, after, token);
      after = response.repository.vulnerabilityAlerts.pageInfo.endCursor;
      for (const dependency of response.repository.vulnerabilityAlerts.nodes) {
        let version = 'na';
        if (dependency.securityVulnerability.firstPatchedVersion != null)
          version = dependency.securityVulnerability.firstPatchedVersion.identifier;
        const row: string[] = [
          dependency.securityVulnerability.advisory.ghsaId,
          dependency.securityVulnerability.package.name,
          dependency.securityVulnerability.package.ecosystem,
          dependency.securityVulnerability.advisory.severity,
          version,
          dependency.securityVulnerability.advisory.description
        ];
        csvData.push(row);
      }
    } while (response.repository.vulnerabilityAlerts.pageInfo.hasNextPage);
    return csvData;
  } catch (error) {
    if (error instanceof Error) {
      core.error(error.message);
      csvData.push([error.message, '', '', '', '']);
    }
    return csvData;
  }
}

async function fetchAPIResults(
  login: string,
  repoName: string,
  after: string,
  token: string
): Promise<any> {
  const response: any = await graphql(getQuery(login, repoName, after), {
    headers: {
      authorization: `token ${token}`,
      accept: 'application/vnd.github.hawkgirl-preview+json'
    }
  });
  return response;
}

function getQuery(login: string, repoName: string, after: string): string {
  const query = `
      {
        repository(owner: "${login}", name: "${repoName}") {
          vulnerabilityAlerts(first: 100 ${after ? `, after: "${after}"` : ''}) {
            nodes {
              createdAt
              dismissedAt
              securityVulnerability {
                package {
                  name
                  ecosystem
                }
                advisory {
                  description
                  permalink
                  severity
                  ghsaId
                }
                firstPatchedVersion {
                  identifier
                }
              }
            }
            totalCount
            pageInfo {
              hasNextPage
              endCursor
            }
          }
        }
      }
    `;
  return query;
}

async function createExcel(allData: { [key: string]: RepositoryData }): Promise<void> {
  for (const repo in allData) {
    const { dgIssues, csIssues, dgInfo, secretScanningAlerts } = allData[repo];
    const wb = xlsx.utils.book_new();

    const ws1 = xlsx.utils.aoa_to_sheet(dgIssues);
    const ws2 = xlsx.utils.aoa_to_sheet(csIssues);
    const ws3 = xlsx.utils.aoa_to_sheet(dgInfo);
    const ws4 = xlsx.utils.aoa_to_sheet(secretScanningAlerts);

    xlsx.utils.book_append_sheet(wb, ws1, `${repo}_dgIssues`);
    xlsx.utils.book_append_sheet(wb, ws2, `${repo}_csIssues`);
    xlsx.utils.book_append_sheet(wb, ws3, `${repo}_dgInfo`);
    xlsx.utils.book_append_sheet(wb, ws4, `${repo}_secretScanningAlerts`);

    const excelFileName = `${repo}_alerts.xlsx`;
    const excelFilePath = path.join(__dirname, excelFileName);

    xlsx.writeFile(wb, excelFilePath);
  }
}

run();
