use crate::GenId;

/// Generations to delete, ascending. Keeps the newest `keep`, every id in `protected`,
/// and gen-1 (the install baseline). Protected ids older than the cutoff survive in addition
/// to the newest `keep`.
pub fn gc_select(gens: &[GenId], keep: usize, protected: &[GenId]) -> Vec<GenId> {
    let mut sorted = gens.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let cutoff = sorted.len().saturating_sub(keep);
    sorted
        .into_iter()
        .take(cutoff)
        .filter(|g| g.0 != 1 && !protected.contains(g))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GenId;

    fn ids(v: &[u32]) -> Vec<GenId> {
        v.iter().map(|&n| GenId(n)).collect()
    }

    #[test]
    fn keeps_newest_k() {
        let gens = ids(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(gc_select(&gens, 5, &[]), ids(&[2, 3]));
    }

    #[test]
    fn never_deletes_gen_one() {
        let gens = ids(&[1, 2, 3]);
        assert_eq!(gc_select(&gens, 1, &[]), ids(&[2]));
    }

    #[test]
    fn never_deletes_protected() {
        let gens = ids(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(gc_select(&gens, 2, &ids(&[3, 5])), ids(&[2, 4, 6]));
    }

    #[test]
    fn nothing_to_delete_when_few_gens() {
        assert!(gc_select(&ids(&[1, 2]), 5, &[]).is_empty());
        assert!(gc_select(&[], 5, &[]).is_empty());
    }

    #[test]
    fn handles_unsorted_and_duplicate_input() {
        let gens = ids(&[8, 2, 5, 2, 7, 3]);
        assert_eq!(gc_select(&gens, 2, &[]), ids(&[2, 3, 5]));
    }

    #[test]
    fn keep_zero_still_respects_protection() {
        let gens = ids(&[1, 2, 3]);
        assert_eq!(gc_select(&gens, 0, &ids(&[3])), ids(&[2]));
    }

    #[test]
    fn keep_zero_unprotected_still_keeps_gen_one() {
        assert_eq!(gc_select(&ids(&[1, 2, 3]), 0, &[]), ids(&[2, 3]));
        assert!(gc_select(&ids(&[1]), 0, &[]).is_empty());
    }

    #[test]
    fn unknown_protected_id_is_ignored() {
        let gens = ids(&[1, 2, 3, 4]);
        assert_eq!(gc_select(&gens, 1, &ids(&[99])), ids(&[2, 3]));
    }
}
