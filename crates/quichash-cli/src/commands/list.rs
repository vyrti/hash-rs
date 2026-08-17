use quichash_core::error::HashUtilityError;
use quichash_core::hash::{self, HashRegistry};

/// Handle the list command: display available algorithms
pub fn handle_list_command(json: bool) -> Result<(), HashUtilityError> {
    let algorithms = HashRegistry::list_algorithms();

    if json {
        #[derive(serde::Serialize)]
        struct ListOutput {
            algorithms: Vec<hash::AlgorithmInfo>,
            metadata: ListMetadata,
        }

        #[derive(serde::Serialize)]
        struct ListMetadata {
            timestamp: String,
            algorithm_count: usize,
        }

        let output = ListOutput {
            algorithms: algorithms.clone(),
            metadata: ListMetadata {
                timestamp: chrono::Utc::now().to_rfc3339(),
                algorithm_count: algorithms.len(),
            },
        };

        let json_output = serde_json::to_string_pretty(&output).map_err(|e| {
            HashUtilityError::InvalidArguments {
                message: format!("Failed to serialize JSON: {}", e),
            }
        })?;

        println!("{}", json_output);
    } else {
        println!("\nAvailable Hash Algorithms:\n");
        println!(
            "{:<20} {:>12} {:>15} {:>15}",
            "Algorithm", "Output Bits", "Post-Quantum", "Cryptographic"
        );
        println!("{}", "-".repeat(65));

        for algo in algorithms {
            let pq_status = if algo.post_quantum { "Yes" } else { "No" };
            let crypto_status = if algo.cryptographic { "Yes" } else { "No" };
            println!(
                "{:<20} {:>12} {:>15} {:>15}",
                algo.name, algo.output_bits, pq_status, crypto_status
            );
        }

        println!();
    }

    Ok(())
}
