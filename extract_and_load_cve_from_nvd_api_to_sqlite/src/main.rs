use anyhow::Result;
use dotenvy::dotenv;
use rayon::prelude::*;
use reqwest::Client;
use serde::Deserialize;
use sqlx::{Pool, Sqlite, sqlite::SqlitePoolOptions};
use std::{collections::HashSet, env, time::Duration};
use tokio::time::sleep;

const BASE_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

#[derive(Debug, Deserialize, Clone)]
pub struct Cve {
    pub id: String,
    #[serde(rename = "sourceIdentifier")]
    pub source_identifier: Option<String>,
    pub published: Option<String>,
    #[serde(rename = "lastModified")]
    pub last_modified: Option<String>,
    #[serde(rename = "vulnStatus")]
    pub vuln_status: Option<String>,
    #[serde(rename = "cveTags")]
    pub cve_tags: Option<Vec<CveTag>>,
    pub descriptions: Option<Vec<LangString>>,
    pub metrics: Option<Metrics>,
    pub weaknesses: Option<Vec<Weakness>>,
    pub configurations: Option<Vec<Configuration>>,
    pub references: Option<Vec<Reference>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LangString {
    pub lang: Option<String>,
    pub value: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Metrics {
    #[serde(rename = "cvssMetricV2")]
    pub cvss_metric_v2: Option<Vec<CvssMetricV2>>,
    #[serde(rename = "cvssMetricV30")]
    pub cvss_metric_v30: Option<Vec<CvssMetricV3>>,
    #[serde(rename = "cvssMetricV31")]
    pub cvss_metric_v31: Option<Vec<CvssMetricV3>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CvssMetricV2 {
    pub source: Option<String>,
    #[serde(rename = "type")]
    pub metric_type: Option<String>,
    #[serde(rename = "cvssData")]
    pub cvss_data: Option<CvssDataV2>,
    #[serde(rename = "baseSeverity")]
    pub base_severity: Option<String>,
    #[serde(rename = "exploitabilityScore")]
    pub exploitability_score: Option<f32>,
    #[serde(rename = "impactScore")]
    pub impact_score: Option<f32>,
    #[serde(rename = "acInsufInfo")]
    pub ac_insuf_info: Option<bool>,
    #[serde(rename = "obtainAllPrivilege")]
    pub obtain_all_privilege: Option<bool>,
    #[serde(rename = "obtainUserPrivilege")]
    pub obtain_user_privilege: Option<bool>,
    #[serde(rename = "obtainOtherPrivilege")]
    pub obtain_other_privilege: Option<bool>,
    #[serde(rename = "userInteractionRequired")]
    pub user_interaction_required: Option<bool>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CvssDataV2 {
    pub version: Option<String>,
    #[serde(rename = "vectorString")]
    pub vector_string: Option<String>,
    #[serde(rename = "baseScore")]
    pub base_score: Option<f32>,
    #[serde(rename = "accessVector")]
    pub access_vector: Option<String>,
    #[serde(rename = "accessComplexity")]
    pub access_complexity: Option<String>,
    pub authentication: Option<String>,
    #[serde(rename = "confidentialityImpact")]
    pub confidentiality_impact: Option<String>,
    #[serde(rename = "integrityImpact")]
    pub integrity_impact: Option<String>,
    #[serde(rename = "availabilityImpact")]
    pub availability_impact: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CvssMetricV3 {
    pub source: Option<String>,
    #[serde(rename = "type")]
    pub metric_type: Option<String>,
    #[serde(rename = "cvssData")]
    pub cvss_data: Option<CvssDataV3>,
    #[serde(rename = "baseSeverity")]
    pub base_severity: Option<String>,
    #[serde(rename = "exploitabilityScore")]
    pub exploitability_score: Option<f32>,
    #[serde(rename = "impactScore")]
    pub impact_score: Option<f32>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CvssDataV3 {
    pub version: Option<String>,
    #[serde(rename = "vectorString")]
    pub vector_string: Option<String>,
    #[serde(rename = "baseScore")]
    pub base_score: Option<f32>,
    #[serde(rename = "baseSeverity")]
    pub base_severity: Option<String>,
    #[serde(rename = "attackVector")]
    pub attack_vector: Option<String>,
    #[serde(rename = "attackComplexity")]
    pub attack_complexity: Option<String>,
    #[serde(rename = "privilegesRequired")]
    pub privileges_required: Option<String>,
    #[serde(rename = "userInteraction")]
    pub user_interaction: Option<String>,
    pub scope: Option<String>,
    #[serde(rename = "confidentialityImpact")]
    pub confidentiality_impact: Option<String>,
    #[serde(rename = "integrityImpact")]
    pub integrity_impact: Option<String>,
    #[serde(rename = "availabilityImpact")]
    pub availability_impact: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Weakness {
    pub source: Option<String>,
    #[serde(rename = "type")]
    pub weakness_type: Option<String>,
    pub description: Option<Vec<LangString>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Configuration {
    pub nodes: Option<Vec<ConfigNode>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ConfigNode {
    pub operator: Option<String>,
    pub negate: Option<bool>,
    #[serde(rename = "cpeMatch")]
    pub cpe_match: Option<Vec<CpeMatch>>,
    pub children: Option<Vec<ConfigNode>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CpeMatch {
    pub vulnerability: Option<bool>,
    pub criteria: Option<String>,
    #[serde(rename = "matchCriteriaId")]
    pub match_criteria_id: Option<String>,
    #[serde(rename = "versionStartIncluding")]
    pub version_start_including: Option<String>,
    #[serde(rename = "versionStartExcluding")]
    pub version_start_excluding: Option<String>,
    #[serde(rename = "versionEndIncluding")]
    pub version_end_including: Option<String>,
    #[serde(rename = "versionEndExcluding")]
    pub version_end_excluding: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Reference {
    pub url: Option<String>,
    pub source: Option<String>,
    pub tags: Option<Vec<String>>,
}
#[derive(Debug, serde::Deserialize)]
pub struct Feed {
    #[serde(rename = "resultsPerPage")]
    pub results_per_page: Option<u32>,
    #[serde(rename = "startIndex")]
    pub start_index: Option<u32>,
    #[serde(rename = "totalResults")]
    pub total_results: Option<u32>,
    pub format: Option<String>,
    pub version: Option<String>,
    pub timestamp: Option<String>,
    pub vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, serde::Deserialize)]
pub struct Vulnerability {
    pub cve: Cve,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CveTag {
    #[serde(rename = "sourceIdentifier")]
    pub source_identifier: Option<String>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug)]
struct ExtractedCve {
    id: String,
    source_identifier: Option<String>,
    published: Option<String>,
    last_modified: Option<String>,
    vuln_status: Option<String>,
    description_en: Option<String>,
    cvssv2_base_score: Option<f32>,
    cvssv2_vector: Option<String>,
    cvssv3_base_score: Option<f32>,
    cvssv3_vector: Option<String>,
    cpes: Vec<String>,
    references: Vec<String>,
    weaknesses: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct CveApiResponse {
    #[serde(rename = "resultsPerPage")]
    pub results_per_page: usize,
    #[serde(rename = "startIndex")]
    pub start_index: usize,
    #[serde(rename = "totalResults")]
    pub total_results: usize,
    pub vulnerabilities: Vec<Vulnerability>,
}

fn collect_cpe_from_nodes(nodes: &Vec<ConfigNode>, out: &mut HashSet<String>) {
    for node in nodes {
        if let Some(cpe_matches) = &node.cpe_match {
            for m in cpe_matches {
                if let Some(criteria) = &m.criteria {
                    out.insert(criteria.clone());
                }
            }
        }
        if let Some(children) = &node.children {
            collect_cpe_from_nodes(children, out);
        }
    }
}

fn extract_from_cve(cve: &Cve) -> ExtractedCve {
    let description_en = cve.descriptions.as_ref().and_then(|desc_list| {
        desc_list.iter().find_map(|d| {
            if d.lang.as_deref() == Some("en") {
                d.value.clone()
            } else {
                None
            }
        })
    });

    let (cvssv2_base_score, cvssv2_vector) = cve
        .metrics
        .as_ref()
        .and_then(|m| m.cvss_metric_v2.as_ref())
        .and_then(|vec| vec.get(0))
        .map(|m| {
            let base = m.cvss_data.as_ref().and_then(|d| d.base_score);
            let vec_str = m
                .cvss_data
                .as_ref()
                .and_then(|d| d.vector_string.as_ref().cloned());
            (base, vec_str)
        })
        .unwrap_or((None, None));

    let (cvssv3_base_score, cvssv3_vector) = cve
        .metrics
        .as_ref()
        .and_then(|m| {
            m.cvss_metric_v31
                .as_ref()
                .or_else(|| m.cvss_metric_v30.as_ref())
        })
        .and_then(|vec| vec.get(0))
        .map(|m| {
            let base = m.cvss_data.as_ref().and_then(|d| d.base_score);
            let vec_str = m
                .cvss_data
                .as_ref()
                .and_then(|d| d.vector_string.as_ref().cloned());
            (base, vec_str)
        })
        .unwrap_or((None, None));

    let mut cpes = HashSet::new();
    if let Some(configs) = &cve.configurations {
        for cfg in configs {
            if let Some(nodes) = &cfg.nodes {
                collect_cpe_from_nodes(nodes, &mut cpes);
            }
        }
    }
    let mut cpes_vec: Vec<String> = cpes.into_iter().collect();
    cpes_vec.sort();

    let mut refs = HashSet::new();
    if let Some(refs_list) = &cve.references {
        for r in refs_list {
            if let Some(url) = &r.url {
                refs.insert(url.clone());
            }
        }
    }
    let mut refs_vec: Vec<String> = refs.into_iter().collect();
    refs_vec.sort();

    let mut weaknesses = Vec::new();
    if let Some(weakness) = &cve.weaknesses {
        for w in weakness {
            if let Some(desc) = &w.description {
                for d in desc {
                    if let Some(v) = &d.value {
                        weaknesses.push(v.clone())
                    }
                }
            }
        }
    }

    ExtractedCve {
        id: cve.id.clone(),
        source_identifier: cve.source_identifier.clone(),
        published: cve.published.clone(),
        last_modified: cve.last_modified.clone(),
        vuln_status: cve.vuln_status.clone(),
        description_en,
        cvssv2_base_score,
        cvssv2_vector,
        cvssv3_base_score,
        cvssv3_vector,
        cpes: cpes_vec,
        references: refs_vec,
        weaknesses,
    }
}

async fn setup_database(pool: &Pool<Sqlite>) -> Result<()> {
    sqlx::query!(
        r#"
        CREATE TABLE IF NOT EXISTS cves (
            id TEXT PRIMARY KEY NOT NULL,
            source_identifier TEXT,
            published TEXT,
            last_modified TEXT,
            vuln_status TEXT,
            description_en TEXT,
            cvssv2_base_score REAL,
            cvssv2_vector TEXT,
            cvssv3_base_score REAL,
            cvssv3_vector TEXT,
            cpes TEXT,
            "references" TEXT, 
            weaknesses TEXT 
        );
        "#
    )
    .execute(pool)
    .await?;

    println!("Database table 'cves' ensured to exist.");
    Ok(())
}

async fn upsert_cves(pool: &Pool<Sqlite>, cves: &[ExtractedCve]) -> Result<()> {
    let mut tx = pool.begin().await?;

    for cve in cves {
        let cpes_json = serde_json::to_string(&cve.cpes)?;
        let refs_json = serde_json::to_string(&cve.references)?;
        let weaknesses_json = serde_json::to_string(&cve.weaknesses)?;

        sqlx::query!(
            r#"
            INSERT INTO cves (
                id,
                source_identifier,
                published,
                last_modified,
                vuln_status,
                description_en,
                cvssv2_base_score,
                cvssv2_vector,
                cvssv3_base_score,
                cvssv3_vector,
                cpes,
                "references",
                weaknesses 
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (id) DO UPDATE SET
                source_identifier = excluded.source_identifier,
                published = excluded.published,
                last_modified = excluded.last_modified,
                vuln_status = excluded.vuln_status,
                description_en = excluded.description_en,
                cvssv2_base_score = excluded.cvssv2_base_score,
                cvssv2_vector = excluded.cvssv2_vector,
                cvssv3_base_score = excluded.cvssv3_base_score,
                cvssv3_vector = excluded.cvssv3_vector,
                cpes = excluded.cpes,
                "references" = excluded."references",
                weaknesses = excluded.weaknesses
            "#,
            cve.id,
            cve.source_identifier,
            cve.published,
            cve.last_modified,
            cve.vuln_status,
            cve.description_en,
            cve.cvssv2_base_score,
            cve.cvssv2_vector,
            cve.cvssv3_base_score,
            cve.cvssv3_vector,
            cpes_json,
            refs_json,
            weaknesses_json,
        )
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    println!("Successfully upserted {} CVE records.", cves.len());

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    let start_time = std::time::Instant::now();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env file");
    let api_key = env::var("NVD_API_KEY").expect("NVD_API_KEY must be set in .env file");

    println!("Connecting to database ...");
    let pool = SqlitePoolOptions::new()
        .max_connections(100)
        .connect(&database_url)
        .await?;
    setup_database(&pool).await?;

    let client = Client::new();

    let mut start_index = 0u32;
    let results_per_page = 2000u32;
    let mut total_results = None;
    let mut total_inserted_count = 0;

    println!("Starting NVD CVE data synchronization...");

    loop {
        let url = format!(
            "{}?resultsPerPage={}&startIndex={}",
            BASE_URL, results_per_page, start_index
        );

        println!("Fetching page: startIndex={}", start_index);

        let response = client
            .get(&url)
            .header("apiKey", &api_key)
            .send()
            .await?
            .error_for_status()?;

        let text = response.text().await?;

        let resp: CveApiResponse = match serde_json::from_str(&text) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("\n--- DESERIALIZATION ERROR ---");
                eprintln!(
                    "Failed to parse JSON response at startIndex={}",
                    start_index
                );
                eprintln!("Error: {}", e);
                //eprintln!("Raw Response Body ({} chars):\n{}", text.len(), text);
                eprintln!("-----------------------------\n");
                return Err(anyhow::anyhow!("JSON deserialization failed: {}", e));
            }
        };

        let extracted_list: Vec<ExtractedCve> = resp
            .vulnerabilities
            .par_iter()
            .map(|vuln| extract_from_cve(&vuln.cve))
            .collect();

        let fetched_count = extracted_list.len();

        let insert_count = extracted_list.len();
        if insert_count > 0 {
            upsert_cves(&pool, &extracted_list).await?;
            total_inserted_count += insert_count;
            println!("--> Successfully upserted {} CVEs.", insert_count);
        }

        if total_results.is_none() {
            total_results = Some(resp.total_results);
            println!(
                "Initial metadata: Total CVEs in feed: {}",
                resp.total_results
            );
        }

        start_index += results_per_page;

        if let Some(total) = total_results {
            if start_index >= total as u32 || fetched_count == 0 {
                break;
            }
        }

        sleep(Duration::from_millis(500)).await;
    }

    println!("\nSynchronization complete!");
    println!("Total CVEs upserted: {}", total_inserted_count);
    println!("Total run time: {:.2?}", start_time.elapsed());

    Ok(())
}
