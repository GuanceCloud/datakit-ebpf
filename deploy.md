# eBPF-based Tracing

## 简介

开启 eBPF 链路功能需要在 datakit ebpf 采集器开启 ebpf-net,ebpf-trace 和插件，并允许采集 httpflow 数据；

由于 ebpf 采集器采集到的是分布式的链路数据且未使用 uprobe 等技术对应用程序进行 trace 信息的注入，因此除非部署了应用侧链路系统是无法传递 trace id 的，但我们会从请求信息中获取 trace id，并可选择是否使用其作为 eBPF 链路的 traceid 来关联应用侧链路；

对于进程内的网络调用关系只能通过 thread id 或 golang goroutine id 进行线程/协程内的跟踪和关联，而在进程与进程间的网络调用关系的跟踪和关联只能主要通过 tcp 序列号进行关联。这导致我们只能设置一个 span 的链接服务，或通过在查询时关联等方式实现 eBPF span 之间关联；

## 部署

所有的 DataKit 的 eBPF 采集器需要配置同一个 trace server 的地址并将采集到的链路 span 数据需要传输到这个 span 链接处理器（如 datakit ebpftrace 采集器）进行链路 span 的链接和 trace id 的生成。

DataKit 的 ebpftrace 采集器启动后将在 DataKit 的服务上（xxxx:9529）创建路由 `/v1/bpftracing`，可以接收来自 eBPF 采集器的链路数据。

可以通过配置文件或者环境变量进行配置，开启 ebpftrace 和 ebpf 采集器

注意：

1. 如果数据量在 1e6 span/min，目前需要至少提供 4C 的 cpu 资源和 4G 的 mem 资源。

1. ebpftrace 采集器默认的链接窗口为 20s，采样率为 0.1。

1. 如果开启系统内所有进程的采集，建议配合进程名黑名单对 containerd, docker 等程序进行过滤；由于放置了 uprobe 探针在 go 程序的 `runtime.execute` goroutine 调度函数上，这可能会造成 50 ～ 100 ns -->  1000+ ns 的协程切换开销。

安装/升级:

```notset
DK_DATAWAY=https://openway.guance.com?token=<TOKEN> bash -c "$(curl -L https://zhuyun-static-files-testing.oss-cn-hangzhou.aliyuncs.com/datakit/install-1.16.0-10-g62b883d850.sh)"


DK_UPGRADE=1 bash -c "$(curl -L https://zhuyun-static-files-testing.oss-cn-hangzhou.aliyuncs.com/datakit/install-1.16.0-10-g62b883d850.sh)"
```

镜像：

```notset
pubrepo.jiagouyun.com/datakit/datakit:1.16.0-10-g62b883d850
```

### datakit-ebpf 外部采集器

> /usr/local/datakit/conf.d/host/

如果需要给被采集进程配置 service name，需要在被采集的程序上设置以下任意一个环境变量

```notset
DK_BPFTRACE_SERVICE

DD_SERVICE
OTEL_SERVICE_NAME
```

配置文件：

```toml
[[inputs.ebpf]]

  # ... 省略 


  enabled_plugins = [
    "ebpf-net",
    "ebpf-trace"
  ]

  l7net_enabled = [
    "httpflow",
  ]

  ## eBPF trace generation server center address.
  trace_server = ""

  ## trace all processes directly
  ##
  trace_all_process = false
  
  ## trace all processes containing any specified environment variable
  trace_envset = [
    "DK_BPFTRACE_SERVICE",
    "DD_SERVICE",
    "OTEL_SERVICE_NAME",
  ]
  
  ## trace all processes containing any specified process names,
  ## can be used with trace_namedenyset
  ##
  trace_nameset = []
  
  ## deny tracing all processes containing any specified process names
  ##
  trace_namedenyset = [
    
    ## The following two processes are hard-coded to never be traced,
    ## and do not need to be set:
    ##
    # "datakit",
    # "datakit-ebpf",
  ]

  ## conv other trace id to datadog trace id (base 10, 64-bit) 
  conv_to_ddtrace = false
```

环境变量：

| ENV                              | 示例                                               | 描述                                                                             |
| -------------------------------- | -------------------------------------------------- | -------------------------------------------------------------------------------- |
| `ENV_INPUT_EBPF_ENABLED_PLUGINS`   | `ebpf-net,ebpf-trace`                              | 开启 ebpf-net 网络跟踪功能，并在此基础上开启链路功能                             |
| `ENV_INPUT_EBPF_L7NET_ENABLED`     | `httpflow`                                         | 开启 http 协议数据采集                                                           |
| `ENV_INPUT_EBPF_TRACE_SERVER`      | `<datakit ip>:<datakit port>`                      | datakit 的地址，需要开启 datakit ebpftrace 采集器用于接收 eBPF 链路数据          |
| `ENV_INPUT_EBPF_TRACE_ALL_PROCESS` | `false`                                            | 对系统内的所有进程进行跟踪                                                       |
| `ENV_INPUT_EBPF_TRACE_NAMEDENYSET` | `datakit,datakit-ebpf`                             | 最优先，指定进程名的进程将被**禁止采集**链路数据，示例中的进程已被硬编码禁止采集 |
| `ENV_INPUT_EBPF_TRACE_ENVSET`      | `DK_BPFTRACE_SERVICE,DD_SERVICE,OTEL_SERVICE_NAME` | 含有任意指定环境变量的进程的链路数据将被跟踪和上报                               |
| `ENV_INPUT_EBPF_TRACE_NAMESET`     | `chrome,firefox`                                   | 进程名在指定集合内的的进程将被跟踪和上报                                             |
| `ENV_INPUT_EBPF_CONV_TO_DDTRACE`   | `false`                                            | 将所有的应用侧链路 id 转换为 10 进制表示的字符串，兼容用途，非必要不使用         |

## datakit ebpftrace 采集器

配置文件：

> /usr/local/datakit/conf.d/ebpftrace

```toml
[[inputs.ebpftrace]]
  sqlite_path = "/usr/local/datakit/ebpf_spandb"
  use_app_trace_id = true
  window = "20s"
  sampling_rate = 0.1
```

环境变量：

| ENV | 示例 | 描述 |
| - | - | - |
| `ENV_INPUT_EBPFTRACE_USE_APP_TRACE_ID` | `true` | `trace_id` 字段允许从应用侧链路字段 `app_trace_id` (存在时) 替代从 `ebpf_trace_id` 取值，否则只能通过 `app_trace_id` 字段关联应用侧链路 |
| `ENV_INPUT_EBPFTRACE_WINDOW` | `20s` | eBPF 链路 span 关联时间窗口大小，超出此窗口（实际可能的范围 `[win:2*win)`）的 ebpf span 将无法关联 |
| `ENV_INPUT_EBPFTRACE_SAMPLING_RATE` | `0.1` | 采样率，区间范围 `(0, 1]` |
| `ENV_INPUT_EBPFTRACE_SQLITE_PATH` |  | SQLite 数据库文件夹路径，通常不需要设置 |

K8s 上采集器部署示例，需要限制只有一个 pod 运行：

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: datakit-ebpftrace

---

apiVersion: apps/v1
kind: Deployment
metadata:
  name: datakit-ebpftrace
  labels:
    app: deployment-datakit-ebpftrace
  namespace: datakit-ebpftrace
spec:
  replicas: 1
  selector:
    matchLabels:
      app: deployment-datakit-ebpftrace
  template:
    metadata:
      labels:
        app: deployment-datakit-ebpftrace
    spec:
      containers:
      - name: datakit-ebpftrace
        image: pubrepo.jiagouyun.com/ebpf-dev/datakit:1.16.0-9-gd315e9c404
        imagePullPolicy: Always
        ports:
        - containerPort: 9529
          protocol: TCP
        - containerPort: 6060
        resources:
          requests:
            cpu: "200m"
            memory: "256Mi"
          limits:
            cpu: "4000m"
            memory: "8Gi"
        env:
        - name: HOST_IP
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: status.hostIP
        - name: ENV_K8S_NODE_NAME
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: spec.nodeName
        - name: ENV_HTTP_LISTEN
          value: 0.0.0.0:9529
        - name: ENV_DATAWAY
          value: http://192.168.56.101:54321?token=tkn_xxxxx
        - name: ENV_GLOBAL_TAGS
          value: host=__datakit_hostname,host_ip=__datakit_ip
        - name: ENV_DEFAULT_ENABLED_INPUTS
          value: ebpftrace
        - name: ENV_INPUT_EBPFTRACE_WINDOW
          value: "20s"
        - name: ENV_INPUT_EBPFTRACE_SAMPLING_RATE
          value: "0.1"
        - name: ENV_ENABLE_PPROF
          value: "true"
        - name: ENV_PPROF_LISTEN
          value: "0.0.0.0:6060"

---

apiVersion: v1
kind: Service
metadata:
  name: datakit-ebpftrace-service
  namespace: datakit-ebpftrace
spec:
  selector:
    app: deployment-datakit-ebpftrace
  ports:
    - protocol: TCP
      port: 9529
      targetPort: 9529
```
