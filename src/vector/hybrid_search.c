#include "hybrid_search.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define RRF_K 60

static int hybrid_result_cmp_desc(const void *a, const void *b) {
    double sa = ((const HybridResult *)a)->score;
    double sb = ((const HybridResult *)b)->score;
    return (sb > sa) - (sb < sa);
}

/* PRIMA: ogni doc_id di list2 veniva sempre aggiunto come voce separata,
 * anche quando lo stesso documento era già presente in list1 (commento
 * dell'autore: "In una versione reale cercheremmo se doc_id esiste già e
 * sommeremmo lo score"). Un documento trovato sia dal ranking vettoriale
 * sia da quello lessicale compariva quindi due volte con due punteggi
 * RRF parziali invece di un unico punteggio combinato più alto — che è
 * esattamente lo scopo della fusione ibrida (un documento rilevante per
 * entrambi i segnali dovrebbe salire in classifica, non restare diviso).
 * ORA: list2 cerca linearmente in combined (O(len1) per elemento — accettabile
 * per i top-k tipicamente piccoli con cui questa funzione viene chiamata) e
 * somma lo score RRF quando trova un doc_id già presente. Il risultato
 * viene anche ordinato per score decrescente, che l'implementazione
 * precedente non faceva (i risultati erano concatenati, non fusi in
 * classifica). */
int nex_hybrid_rrf(HybridResult *list1, uint32_t len1, HybridResult *list2, uint32_t len2, HybridResult **out_res, uint32_t *out_len) {
    uint32_t max_total = len1 + len2;
    HybridResult *combined = malloc(sizeof(HybridResult) * (max_total > 0 ? max_total : 1));
    uint32_t combined_count = 0;

    for (uint32_t i = 0; i < len1; i++) {
        combined[combined_count].doc_id = strdup(list1[i].doc_id);
        combined[combined_count].score = 1.0 / (double)(i + RRF_K);
        combined_count++;
    }

    for (uint32_t i = 0; i < len2; i++) {
        double score2 = 1.0 / (double)(i + RRF_K);
        int found = -1;
        for (uint32_t j = 0; j < combined_count; j++) {
            if (strcmp(combined[j].doc_id, list2[i].doc_id) == 0) {
                found = (int)j;
                break;
            }
        }
        if (found >= 0) {
            combined[found].score += score2;
        } else {
            combined[combined_count].doc_id = strdup(list2[i].doc_id);
            combined[combined_count].score = score2;
            combined_count++;
        }
    }

    qsort(combined, combined_count, sizeof(HybridResult), hybrid_result_cmp_desc);

    *out_res = combined;
    *out_len = combined_count;
    return 1;
}

/* CROSS-ENCODER RERANKING — STUB, non implementato.
 * Richiede un modello di inferenza reale (locale o remoto via worker AI)
 * per ricalcolare gli score sulla coppia (query, doc_text); questa
 * funzione oggi non fa nulla e ritorna sempre successo senza toccare
 * `results`, quindi l'ordine RRF esistente resta invariato — chi la
 * chiama non deve assumere che il reranking abbia effettivamente avuto
 * luogo. Implementarla richiede: (1) un client per il modello di
 * inferenza, (2) accesso al testo del documento (oggi non presente in
 * HybridResult, solo doc_id+score), (3) test di regressione sulla
 * qualità del ranking — nessuno dei tre esiste ancora in questo
 * codebase. */
int nex_hybrid_rerank(HybridResult *results, uint32_t count, const char *model_name) {
    if (!results || count == 0) return 0;
    (void)model_name;
    return 1;
}
