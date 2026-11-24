package org.cryptomator.jfuse.mac;

import org.cryptomator.jfuse.mac.extr.fuse.fuse_conn_info;
import org.cryptomator.jfuse.mac.extr.fuse.fuse_file_info;
import org.cryptomator.jfuse.mac.extr.fuse.fuse_operations;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static java.lang.foreign.MemoryLayout.PathElement.groupElement;

/**
 * Offsets measured with {@code offsetof} against the macFUSE and FUSE-T headers on arm64 (both identical).
 */
public class DarwinLayoutTest {

	@Test
	@DisplayName("struct sizes")
	public void testSizes() {
		Assertions.assertEquals(464, fuse_operations.sizeof());
		Assertions.assertEquals(128, fuse_conn_info.sizeof());
		Assertions.assertEquals(40, fuse_file_info.sizeof());
	}

	@DisplayName("fuse_operations offsets")
	@ParameterizedTest(name = "{0} at {1}")
	@CsvSource(value = {
			"getattr,0",
			"readlink,8",
			"getdir,16",
			"mknod,24",
			"mkdir,32",
			"unlink,40",
			"rmdir,48",
			"symlink,56",
			"rename,64",
			"link,72",
			"chmod,80",
			"chown,88",
			"truncate,96",
			"utime,104",
			"open,112",
			"read,120",
			"write,128",
			"statfs,136",
			"flush,144",
			"release,152",
			"fsync,160",
			"setxattr,168",
			"getxattr,176",
			"listxattr,184",
			"removexattr,192",
			"opendir,200",
			"readdir,208",
			"releasedir,216",
			"fsyncdir,224",
			"init,232",
			"destroy,240",
			"access,248",
			"create,256",
			"ftruncate,264",
			"fgetattr,272",
			"lock,280",
			"utimens,288",
			"bmap,296",
			"ioctl,312",
			"poll,320",
			"write_buf,328",
			"read_buf,336",
			"flock,344",
			"fallocate,352",
			"reserved00,360",
			"monitor,368",
			"renamex,376",
			"statfs_x,384",
			"setvolname,392",
			"exchange,400",
			"getxtimes,408",
			"setbkuptime,416",
			"setchgtime,424",
			"setcrtime,432",
			"chflags,440",
			"setattr_x,448",
			"fsetattr_x,456"
	})
	public void testFuseOperationsOffsets(String member, long offset) {
		Assertions.assertEquals(offset, fuse_operations.layout().byteOffset(groupElement(member)));
	}

	@DisplayName("fuse_conn_info offsets")
	@ParameterizedTest(name = "{0} at {1}")
	@CsvSource(value = {
			"proto_major,0",
			"proto_minor,4",
			"async_read,8",
			"max_write,12",
			"max_readahead,16",
			"enable,20",
			"capable,24",
			"want,28",
			"max_background,32",
			"congestion_threshold,36",
			"reserved,40"
	})
	public void testFuseConnInfoOffsets(String member, long offset) {
		Assertions.assertEquals(offset, fuse_conn_info.layout().byteOffset(groupElement(member)));
	}

	@DisplayName("fuse_file_info offsets")
	@ParameterizedTest(name = "{0} at {1}")
	@CsvSource(value = {
			"flags,0",
			"fh_old,8",
			"writepage,16",
			"fh,24",
			"lock_owner,32"
	})
	public void testFuseFileInfoOffsets(String member, long offset) {
		Assertions.assertEquals(offset, fuse_file_info.layout().byteOffset(groupElement(member)));
	}

}
