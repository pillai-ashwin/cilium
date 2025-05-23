// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	apiextensionsv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apiextensions-client/clientset/versioned/typed/apiextensions/v1"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/apiextensions/v1"
	gentype "k8s.io/client-go/gentype"
)

// fakeCustomResourceDefinitions implements CustomResourceDefinitionInterface
type fakeCustomResourceDefinitions struct {
	*gentype.FakeClientWithList[*v1.CustomResourceDefinition, *v1.CustomResourceDefinitionList]
	Fake *FakeApiextensionsV1
}

func newFakeCustomResourceDefinitions(fake *FakeApiextensionsV1) apiextensionsv1.CustomResourceDefinitionInterface {
	return &fakeCustomResourceDefinitions{
		gentype.NewFakeClientWithList[*v1.CustomResourceDefinition, *v1.CustomResourceDefinitionList](
			fake.Fake,
			"",
			v1.SchemeGroupVersion.WithResource("customresourcedefinitions"),
			v1.SchemeGroupVersion.WithKind("CustomResourceDefinition"),
			func() *v1.CustomResourceDefinition { return &v1.CustomResourceDefinition{} },
			func() *v1.CustomResourceDefinitionList { return &v1.CustomResourceDefinitionList{} },
			func(dst, src *v1.CustomResourceDefinitionList) { dst.ListMeta = src.ListMeta },
			func(list *v1.CustomResourceDefinitionList) []*v1.CustomResourceDefinition {
				return gentype.ToPointerSlice(list.Items)
			},
			func(list *v1.CustomResourceDefinitionList, items []*v1.CustomResourceDefinition) {
				list.Items = gentype.FromPointerSlice(items)
			},
		),
		fake,
	}
}
