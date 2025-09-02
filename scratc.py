
#open a file for data of a single column
with open('column_data.dat', 'wb') as f:
    #for 1024 "csv files"
    for _ in range(1024):
        csv_data = np.random.rand(1024).astype(np.float) #represents one column of data
        f.write(csv_data.tobytes())

#open the array as a memory-mapped file
column_mmap = np.memmap('column_data.dat', dtype=np.float)

#read some data
print(np.mean(column_mmap[0:1024]))

#write some data
column_mmap[0:512] = .5

#deletion closes the memory-mapped file and flush changes to disk.
#  del isn't specifically needed as python will garbage collect objects no
#  longer accessable. If for example you intend to read the entire array,
#  you will need to periodically make sure the array gets deleted and re-created
#  or the entire thing will end up in memory again. This could be done with a
#  function that loads and operates on part of the array, then when the function
#  returns and the memory-mapped array local to the function goes out of scope,
#  it will be garbage collected. Calling such a function would not cause a
#  build-up of memory usage.
del column_mmap

#write some more data to the array (not while the mmap is open)
with open('column_data.dat', 'ab') as f:
    #for 1024 "csv files"
    for _ in range(1024):
        csv_data = np.random.rand(1024).astype(np.float) #represents one column of data
        f.write(csv_data.tobytes())



            return_list = np.memmap('encrypted.dat', dtype=Seal, mode='w+', shape=(len(i),))
            j = 0
            for val in i:
                pod_matrix = [0] * self.slot_count
                pod_matrix[0] = int(val)
                x_plain = self.batch_encoder.encode(pod_matrix)
                x_encrypted = self.encryptor.encrypt(x_plain)
                return_list[j] = x_encrypted
                j += 1
            return_list.flush()
        

            return_list = np.memmap('plain.dat', dtype=Seal, mode='w+', shape=(len(i),))
            j = 0
            for val in i:
                pod_matrix = [0] * self.slot_count
                pod_matrix[0] = int(val)
                x_plain = self.batch_encoder.encode(pod_matrix)
                # x_encrypted = self.encryptor.encrypt(x_plain)
                return_list[j] = x_plain
                j += 1
            return_list.flush()