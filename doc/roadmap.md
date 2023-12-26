# Initialization

I'm trying to finish this project stage by stage and step by step.

## Stage 1: prepare otlp program
- Prepare a distribution tracing collector and tools(I pick up the `tempo` here).
- Encapsulate the cJSON interface for otlp data format and test the basic tracing function.

## Stage 2: prepare the eBPF framework
- Define the custom eBPF program template.
- Define how to inject eBPF program and prepare the eBPF loader.
- Prepare the userspace data collector.

## Stage3: connect the kernel data flow to distribution 
- Define the key data that eBPF program should collect.
- Send them with otlp to collector.
- Check and analyse the data.
