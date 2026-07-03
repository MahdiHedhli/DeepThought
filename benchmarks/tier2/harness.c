/* libFuzzer + ASan harness around cJSON_ParseWithLength — the parsing sink for
 * CVE/issue #800 (heap over-read in parse_string). It reads the sink; it does
 * not authorize anything. Deterministic single-input replay: run `harness FILE`.
 */
#include <stddef.h>
#include <stdint.h>
#include "cJSON.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cJSON *item = cJSON_ParseWithLength((const char *)data, size);
    cJSON_Delete(item);
    return 0;
}
