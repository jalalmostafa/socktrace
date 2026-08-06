package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

type RingChannel[T any] struct {
	context   context.Context
	canceller context.CancelFunc
	Channel   chan T
	reader    *ringbuf.Reader
}

func (ring *RingChannel[T]) Fetch() (T, error) {
	var event T

	record, err := ring.reader.Read()
	if err != nil {
		return event, err
	}

	err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
	if err != nil {
		return event, err
	}

	return event, nil
}

func (ring *RingChannel[T]) Init(ringbuffer *ebpf.Map) error {
	var err error = nil

	ring.reader, err = ringbuf.NewReader(ringbuffer)
	if err != nil {
		return err
	}

	ring.context, ring.canceller = context.WithCancel(context.Background())
	ring.Channel = make(chan T, 100)
	go func() {
		for {
			select {
			case <-ring.context.Done():
				return
			default:
				event, err := ring.Fetch()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					continue
				}
				select {
				case <-ring.context.Done():
					return
				case ring.Channel <- event:
				}
			}
		}
	}()
	return nil
}

func (ring *RingChannel[T]) Close() {
	if ring.reader != nil {
		ring.reader.Close()
	}

	if ring.canceller != nil {
		ring.canceller()
	}

	if ring.Channel != nil {
		close(ring.Channel)
	}
}
