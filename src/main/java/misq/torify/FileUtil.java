/*
 * This file is part of Bisq.
 *
 * Bisq is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * Bisq is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Bisq. If not, see <http://www.gnu.org/licenses/>.
 */

package misq.torify;

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.compressors.xz.XZCompressorInputStream;

import java.io.BufferedReader;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;

import java.util.Scanner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FileUtil {
    private static final Logger log = LoggerFactory.getLogger(FileUtil.class);

    public static void makeDirs(File dir) throws IOException {
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IOException("Could not make dir " + dir);
        }
    }

    public static void makeFile(File file) throws IOException {
        if (!file.exists() && !file.createNewFile()) {
            throw new IOException("Could not make file " + file);
        }
    }

    public static void writeToFile(String string, File file) throws IOException {
        try (FileWriter fileWriter = new FileWriter(file.getAbsolutePath())) {
            fileWriter.write(string);
        } catch (IOException e) {
            log.warn("Could not {} to file {}", string, file);
            throw e;
        }
    }

    public static String readFromFile(File file) throws FileNotFoundException {
        StringBuilder sb = new StringBuilder();
        try (Scanner scanner = new Scanner(file)) {
            while (scanner.hasNextLine()) {
                sb.append(scanner.nextLine());
            }
        }
        return sb.toString();
    }

    public static InputStream getResourceAsStream(String fileName) throws IOException {
        InputStream resource = FileUtil.class.getResourceAsStream(fileName);
        if (resource == null) {
            throw new IOException("Could not load " + fileName);
        }
        return resource;
    }

    public static void resourceToFile(File file) throws IOException {
        InputStream resource = getResourceAsStream("/" + file.getName());
        if (file.exists() && !file.delete()) {
            throw new IOException("Could not remove existing file " + file.getName());
        }
        OutputStream out = new FileOutputStream(file);
        copy(resource, out);
    }

    public static void appendFromResource(PrintWriter printWriter, String pathname) {
        try (InputStream inputStream = FileUtil.class.getResourceAsStream(pathname);
             BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream))) {
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                printWriter.println(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void copy(InputStream inputStream, OutputStream outputStream) throws IOException {
        try (outputStream) {
            byte[] buffer = new byte[4096];
            while (true) {
                int read = inputStream.read(buffer);
                if (read == -1) break;
                outputStream.write(buffer, 0, read);
            }
        }
    }

    public static byte[] asBytes(File file) throws IOException {
        byte[] bytes = new byte[(int) file.length()];
        try (FileInputStream inputStream = new FileInputStream(file)) {
            int offset = 0;
            while (offset < bytes.length) {
                int read = inputStream.read(bytes, offset, bytes.length - offset);
                if (read == -1) throw new EOFException();
                offset += read;
            }
            return bytes;
        }
    }

    public static void extractBinary(String torDirectory, OsType osType) throws IOException {
        InputStream archiveInputStream = FileUtil.getResourceAsStream(osType.getArchiveName());
        try (XZCompressorInputStream compressorInputStream = new XZCompressorInputStream(archiveInputStream);
             TarArchiveInputStream tarArchiveInputStream = new TarArchiveInputStream(compressorInputStream)) {
            ArchiveEntry entry;
            while ((entry = tarArchiveInputStream.getNextEntry()) != null) {
                File file = new File(torDirectory + File.separator +
                        entry.getName().replace('/', File.separatorChar));

                if (entry.isDirectory()) {
                    if (!file.exists() && !file.mkdirs()) {
                        throw new IOException("Could not create directory. File= " + file);
                    }
                    continue;
                   // return;
                }

                if (!file.getParentFile().exists() && !file.getParentFile().mkdirs()) {
                    throw new IOException("Could not create parent directory. File= " + file.getParentFile());
                }

                if (file.exists() && !file.delete()) {
                    throw new IOException("Could not delete file in preparation for overwriting it. File= " + file.getAbsolutePath());
                }

                if (!file.createNewFile()) {
                    throw new IOException("Could not create file. File= " + file);
                }

                FileOutputStream fileOutputStream = new FileOutputStream(file);
                tarArchiveInputStream.transferTo(fileOutputStream);

                if (osType == OsType.MACOS) {
                    if (!file.setExecutable(true, true)) {
                        throw new IOException("Cannot set permission at file " + file.getAbsolutePath());
                    }
                } else if (entry instanceof TarArchiveEntry) {
                    int mode = ((TarArchiveEntry) entry).getMode();
                    log.debug("mode={} for file {}", mode, file);
                    if (mode + 65 > 0) {
                        boolean ownerOnly = mode + 1 == 0;
                        log.debug("ownerOnly={} for file {}", ownerOnly, file);
                        if (!file.setExecutable(true, ownerOnly)) {
                            throw new IOException("Cannot set permission at file " + file.getAbsolutePath());
                        }
                    }
                }
            }
        }
    }
}
