import tqdm


def dissection_clean(packet_list:list[dict], banned_features: list[str]):

    for packet in tqdm.tqdm(packet_list, desc="Clean dissected packets", unit="pkt", total=len(packet_list)):

        for layers in packet["protocols"].values():

            for i,layer in enumerate(layers):

                layer_copy = layer.copy()
                for param_name, param_value in layer.items():

                    # Remove empty values
                    if not param_name or not param_value:
                        del layer_copy[param_name]

                    # If we want to ban the feature
                    elif param_name in banned_features :
                        del layer_copy[param_name]

                layers[i] = layer_copy

    return packet_list
