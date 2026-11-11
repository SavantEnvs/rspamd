/* Archive listing: ZIP / RAR / 7z / gzip readers, reached through a one-part message. */
#include "fuzz_init.h"
#include "libserver/task.h"
#include "libmime/message.h"
#include "libmime/archives.h"

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
	fuzz_rspamd_init();
	return 0;
}

static const char skeleton[] = "Content-Type: application/octet-stream\r\n\r\nx";

/* The first input byte picks the reader: the rest is the archive as it would be after transfer decoding */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const char *const exts[] = {"zip", "rar", "7z", "gz"};

	if (size < 8 || size > (1u << 20)) {
		return -1;
	}

	char *buf = (char *) g_malloc(size - 1);
	memcpy(buf, data + 1, size - 1);

	struct rspamd_task *task = rspamd_task_new(NULL, fuzz_cfg, NULL, NULL, NULL, FALSE);
	task->msg.begin = skeleton;
	task->msg.len = sizeof(skeleton) - 1;
	int ret = -1;

	if (rspamd_message_parse(task) && MESSAGE_FIELD(task, parts)->len > 0) {
		struct rspamd_mime_part *part =
			(struct rspamd_mime_part *) g_ptr_array_index(MESSAGE_FIELD(task, parts), 0);

		part->parsed_data.begin = buf;
		part->parsed_data.len = size - 1;
		part->detected_ext = rspamd_mempool_strdup(task->task_pool, exts[data[0] & 3]);
		rspamd_archives_process(task);
		ret = 0;
	}

	rspamd_task_free(task);
	g_free(buf);

	return ret;
}
