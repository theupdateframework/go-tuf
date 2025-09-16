// Copyright 2024 The Update Framework Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
//
// SPDX-License-Identifier: Apache-2.0
//

package simulator

import "github.com/theupdateframework/go-tuf/v2/metadata"

type SimulatorOption interface {
	apply(*RepositorySimulator)
}

type DelegatesOption map[string]metadata.Metadata[metadata.TargetsType]

func (o DelegatesOption) apply(s *RepositorySimulator) {
	s.MDDelegates = o
}

func WithDelegates(delegates map[string]metadata.Metadata[metadata.TargetsType]) SimulatorOption {
	return DelegatesOption(delegates)
}
