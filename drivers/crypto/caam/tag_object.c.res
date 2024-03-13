diff a/drivers/crypto/caam/tag_object.c b/drivers/crypto/caam/tag_object.c	(rejected hunks)
@@ -1,6 +1,6 @@
-// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
+// SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause)
 /*
- * Copyright 2018-2019 NXP
+ * Copyright 2018-2020 NXP
  */
 
 #include <linux/export.h>
@@ -10,251 +10,155 @@
 #include "tag_object.h"
 #include "desc.h"
 
-/*
- * Magic number to clearly identify the structure is for us
- * 0x54 = 'T'
- * 0x61 = 'a'
- * 0x67 = 'g'
- * 0x4f = 'O'
- */
-#define TAG_OBJECT_MAGIC 0x5461674f
-
-/**
- * struct tagged_object - Structure representing a tagged object
- * @tag : The configuration of the data
- * @object : The object
- */
-struct tagged_object {
-	struct tag_object_conf tag;
-	char object;
-};
-
 /**
- * is_bk_type() - Determines if black key type.
- * @type: The type
+ * is_key_type -	Check if the object is a key
  *
- * Return: True if black key type, False otherwise.
- */
-static bool is_bk_type(enum tag_type type)
-{
-	return (type == TAG_TYPE_BLACK_KEY_ECB) ||
-		(type == TAG_TYPE_BLACK_KEY_ECB_TRUSTED) ||
-		(type == TAG_TYPE_BLACK_KEY_CCM) ||
-		(type == TAG_TYPE_BLACK_KEY_CCM_TRUSTED);
-}
-
-/**
- * is_bk_conf() - Determines if black key conf.
- * @tag_obj_conf : The tag object conf
+ * @type:		The object type
  *
- * Return: True if black key conf, False otherwise.
+ * Return:		True if the object is a key (of black or red color),
+ *			false otherwise
  */
-bool is_bk_conf(const struct tag_object_conf *tag_obj_conf)
+bool is_key_type(u32 type)
 {
-	return is_bk_type(tag_obj_conf->header.type);
+	/* Check type bitfield from object type */
+	return ((type >> TAG_OBJ_TYPE_OFFSET) & TAG_OBJ_TYPE_MASK) == 0;
 }
-EXPORT_SYMBOL(is_bk_conf);
+EXPORT_SYMBOL(is_key_type);
 
 /**
- * get_bk_conf() - Gets the block conf.
- * @tag_obj_conf : The tag object conf
+ * is_trusted_type -	Check if the object is a trusted key
+ *			Trusted Descriptor Key Encryption Key (TDKEK)
  *
- * Return: The block conf.
- */
-const struct blackey_conf *get_bk_conf(const struct tag_object_conf *tag_obj_conf)
-{
-	return &tag_obj_conf->conf.bk_conf;
-}
-
-/**
- * get_tag_object_overhead() - Gets the tag object overhead.
+ * @type:		The object type
  *
- * Return: The tag object overhead.
+ * Return:		True if the object is a trusted key,
+ *			false otherwise
  */
-size_t get_tag_object_overhead(void)
+bool is_trusted_type(u32 type)
 {
-	return TAG_OVERHEAD;
+	/* Check type bitfield from object type */
+	return ((type >> TAG_OBJ_TK_OFFSET) & TAG_OBJ_TK_MASK) == 1;
 }
-EXPORT_SYMBOL(get_tag_object_overhead);
+EXPORT_SYMBOL(is_trusted_type);
 
 /**
- * is_valid_type() - Determines if valid type.
- * @type : The type
+ * is_black_key -	Check if the tag object header is a black key
+ * @header:		The tag object header configuration
  *
- * Return: True if valid type, False otherwise.
+ * Return:		True if is a black key, false otherwise
  */
-bool is_valid_type(enum tag_type type)
+bool is_black_key(const struct header_conf *header)
 {
-	return (type > TAG_TYPE_NOT_SUPPORTED) && (type < NB_TAG_TYPE);
+	u32 type = header->type;
+	/* Check type and color bitfields from tag object type */
+	return (type & (BIT(TAG_OBJ_COLOR_OFFSET) |
+			BIT(TAG_OBJ_TYPE_OFFSET))) == BIT(TAG_OBJ_COLOR_OFFSET);
 }
-EXPORT_SYMBOL(is_valid_type);
+EXPORT_SYMBOL(is_black_key);
 
 /**
- * is_valid_header() - Determines if valid header.
- * @header : The header
+ * is_valid_header_conf - Check if the header configuration is valid
+ * @header:		The header configuration
  *
- * Return: True if valid tag object conf, False otherwise.
+ * Return:		True if the header of the tag object configuration,
+ *			has the TAG_OBJECT_MAGIC number and a valid type,
+ *			false otherwise
  */
-static bool is_valid_header(const struct conf_header *header)
+bool is_valid_header_conf(const struct header_conf *header)
 {
-	bool valid = header->_magic_number == TAG_OBJECT_MAGIC;
-
-	valid = valid && is_valid_type(header->type);
-
-	return valid;
+	return (header->_magic_number == TAG_OBJECT_MAGIC);
 }
+EXPORT_SYMBOL(is_valid_header_conf);
 
 /**
- * is_valid_tag_object_conf() - Determines if valid tag object conf.
- * @tag_obj_conf : The tag object conf
- *
- * Return: True if valid header, False otherwise.
- */
-bool is_valid_tag_object_conf(const struct tag_object_conf *tag_obj_conf)
+ * get_key_conf -	Retrieve the key configuration,
+ *			meaning the length of the black key and
+ *			the KEY command parameters needed for CAAM
+ * @header:		The tag object header configuration
+ * @red_key_len:	Red key length
+ * @obj_len:		Black/Red key/blob length
+ * @load_param:		Load parameters for KEY command:
+ *			- indicator for encrypted keys: plaintext or black
+ *			- indicator for encryption mode: AES-ECB or AES-CCM
+ *			- indicator for encryption keys: JDKEK or TDKEK
+ */
+void get_key_conf(const struct header_conf *header,
+		  u32 *red_key_len, u32 *obj_len, u32 *load_param)
 {
-	bool valid = true;
-
-	valid = is_valid_header(&tag_obj_conf->header);
-
-	return valid;
+	*red_key_len = header->red_key_len;
+	*obj_len = header->obj_len;
+	/* Based on the color of the key, set key encryption bit (ENC) */
+	*load_param = ((header->type >> TAG_OBJ_COLOR_OFFSET) &
+		       TAG_OBJ_COLOR_MASK) << KEY_ENC_OFFSET;
+	/*
+	 * For red keys, the TK and EKT bits are ignored.
+	 * So we set them anyway, to be valid when the key is black.
+	 */
+	*load_param |= ((header->type >> TAG_OBJ_TK_OFFSET) &
+			 TAG_OBJ_TK_MASK) << KEY_TK_OFFSET;
+	*load_param |= ((header->type >> TAG_OBJ_EKT_OFFSET) &
+			 TAG_OBJ_EKT_MASK) << KEY_EKT_OFFSET;
 }
-EXPORT_SYMBOL(is_valid_tag_object_conf);
+EXPORT_SYMBOL(get_key_conf);
 
 /**
- * get_tag_object_conf() - Gets a pointer on the tag object conf.
- * @tag_obj_conf : The tag object conf
- * @buffer : The buffer
- * @size : The size
- *
- * Return: 0 if success, else error code
- */
-int get_tag_object_conf(const void *buffer, size_t size,
-			struct tag_object_conf **tag_obj_conf)
+ * init_tag_object_header - Initialize the tag object header by setting up
+ *			the TAG_OBJECT_MAGIC number, tag object version,
+ *			a valid type and the object's length
+ * @header:		The header configuration to initialize
+ * @version:		The tag object version
+ * @type:		The tag object type
+ * @red_key_len:	The red key length
+ * @obj_len:		The object (actual data) length
+ */
+void init_tag_object_header(struct header_conf *header, u32 version,
+			    u32 type, size_t red_key_len, size_t obj_len)
 {
-	bool is_valid;
-	struct tagged_object *tago = (struct tagged_object *)buffer;
-	size_t conf_size = get_tag_object_overhead();
-
-	/* Check we can retrieve the conf */
-	if (size < conf_size)
-		return -EINVAL;
-
-	is_valid = is_valid_tag_object_conf(&tago->tag);
-
-	*tag_obj_conf = &tago->tag;
-
-	return (is_valid) ? 0 : -EINVAL;
-}
-EXPORT_SYMBOL(get_tag_object_conf);
-
-/**
- * init_tag_object_header() - Initialize the tag object header
- * @conf_header : The configuration header
- * @type : The type
- *
- * It initialize the header structure
- */
-void init_tag_object_header(struct conf_header *conf_header,
-			    enum tag_type type)
-{
-	conf_header->_magic_number = TAG_OBJECT_MAGIC;
-	conf_header->type = type;
+	header->_magic_number = TAG_OBJECT_MAGIC;
+	header->version = version;
+	header->type = type;
+	header->red_key_len = red_key_len;
+	header->obj_len = obj_len;
 }
 EXPORT_SYMBOL(init_tag_object_header);
 
 /**
- * set_tag_object_conf() - Sets the tag object conf.
- * @tag_obj_conf : The tag object conf
- * @buffer : The buffer
- * @obj_size : The object size
- * @to_size : The tagged object size
- *
- * Return: 0 if success, else error code
- */
-int set_tag_object_conf(const struct tag_object_conf *tag_obj_conf,
-			void *buffer, size_t obj_size, u32 *to_size)
-{
-	struct tagged_object *tago = buffer;
-	size_t conf_size = get_tag_object_overhead();
-	size_t req_size = obj_size + conf_size;
-
-	/* Check we can set the conf */
-	if (*to_size < req_size) {
-		*to_size = req_size;
-		return -EINVAL;
-	}
-
-	/* Move the object */
-	memmove(&tago->object, buffer, obj_size);
-
-	/* Copy the tag */
-	memcpy(&tago->tag, tag_obj_conf, conf_size);
-
-	*to_size = req_size;
-
-	return 0;
-}
-EXPORT_SYMBOL(set_tag_object_conf);
-
-/**
- * init_blackey_conf() - Initialize the black key configuration
- * @blackey_conf : The blackey conf
- * @len : The length
- * @ccm : The ccm
- * @tk : The trusted key
- *
- * It initialize the black key configuration structure
- */
-void init_blackey_conf(struct blackey_conf *blackey_conf,
-		       size_t len, bool ccm, bool tk)
-{
-	blackey_conf->real_len = len;
-	blackey_conf->load = KEY_ENC
-				| ((ccm) ? KEY_EKT : 0)
-				| ((tk) ? KEY_TK : 0);
-}
-EXPORT_SYMBOL(init_blackey_conf);
-
-/**
- * get_blackey_conf() - Get the black key configuration
- * @blackey_conf : The blackey conf
- * @real_len : The real length
- * @load_param : The load parameter
+ * set_tag_object_header_conf - Set tag object header configuration
+ * @header:			The tag object header configuration to set
+ * @buffer:			The buffer needed to be tagged
+ * @buf_size:			The buffer size
+ * @tag_obj_size:		The tagged object size
  *
- * It retrieve the black key configuration
+ * Return:			'0' on success, error code otherwise
  */
-void get_blackey_conf(const struct blackey_conf *blackey_conf,
-		      u32 *real_len, u32 *load_param)
+int set_tag_object_header_conf(const struct header_conf *header,
+			       void *buffer, size_t buf_size, u32 *tag_obj_size)
 {
-	*real_len = blackey_conf->real_len;
-	*load_param = blackey_conf->load;
-}
-EXPORT_SYMBOL(get_blackey_conf);
-
-/**
- * get_tagged_data() - Get a pointer on the data and the size
- * @tagged_object : Pointer on the tagged object
- * @tagged_object_size : tagged object size in bytes
- * @data : Pointer on the data
- * @data_size : data size in bytes
- *
- * Return: 0 if success, else error code
- */
-int get_tagged_data(const void *tagged_object, size_t tagged_object_size,
-		    const void **data, u32 *data_size)
-{
-	struct tagged_object *tago =
-		(struct tagged_object *)tagged_object;
-	size_t conf_size = get_tag_object_overhead();
-
-	/* Check we can retrieve the object */
-	if (tagged_object_size < conf_size)
+	/* Retrieve the tag object */
+	struct tagged_object *tag_obj = (struct tagged_object *)buffer;
+	/*
+	 * Requested size for the tagged object is the buffer size
+	 * and the header configuration size (TAG_OVERHEAD_SIZE)
+	 */
+	size_t req_size = buf_size + TAG_OVERHEAD_SIZE;
+
+	/*
+	 * Check if the configuration can be set,
+	 * based on the size of the tagged object
+	 */
+	if (*tag_obj_size < req_size)
 		return -EINVAL;
 
-	/* Retrieve the object */
-	*data = &tago->object;
-	*data_size = tagged_object_size - conf_size;
+	/*
+	 * Buffers might overlap, use memmove to
+	 * copy the buffer into the tagged object
+	 */
+	memmove(&tag_obj->object, buffer, buf_size);
+	/* Copy the tag object header configuration into the tagged object */
+	memcpy(&tag_obj->header, header, TAG_OVERHEAD_SIZE);
+	/* Set tagged object size */
+	*tag_obj_size = req_size;
 
 	return 0;
 }
-EXPORT_SYMBOL(get_tagged_data);
+EXPORT_SYMBOL(set_tag_object_header_conf);
