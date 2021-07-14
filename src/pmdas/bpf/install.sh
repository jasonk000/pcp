set -e

rm -f bpf.o pmdabpf modules/runqlat.o modules/biolatency.o modules/biolatency.so modules/runqlat.so modules/biolatency.bpf.o modules/runqlat.bpf.o
rm -rf /var/lib/pcp/pmdas/bpf/*

mkdir -p /var/lib/pcp/pmdas/bpf/modules

make
make -C modules/

cp domain.h help Install pmdabpf pmns README Remove root /var/lib/pcp/pmdas/bpf
cp modules/biolatency.bpf.o modules/biolatency.so modules/runqlat.bpf.o modules/runqlat.so /var/lib/pcp/pmdas/bpf/modules
cd /var/lib/pcp/pmdas/bpf && sudo ./Install
