// mcs-vinicius/toxicos/toxicos-main/Frontend/src/components/ranking/RegisterPage.jsx

import React, { useState, useEffect } from "react";
import axios from "axios";
// Ícones atualizados para incluir Edição (FaEdit)
import { FaTrash, FaPlus, FaUpload, FaEdit } from "react-icons/fa"; 
import "../../styles/RegisterPage.css";

const RegisterPage = () => {
  const [participants, setParticipants] = useState([]);
  const [allUsers, setAllUsers] = useState([]);
  const [currentParticipant, setCurrentParticipant] = useState({
    name: "",
    habby_id: null,
    fase: "",
    r1: "",
    r2: "",
    r3: "",
  });
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [loading, setLoading] = useState(false);
  // Novo estado para controlar o índice do participante em edição
  const [editingIndex, setEditingIndex] = useState(null); 

  useEffect(() => {
    const fetchUsers = async () => {
      try {
        const apiUrl = import.meta.env.VITE_API_URL;
        const response = await axios.get(`${apiUrl}/users`);
        setAllUsers(response.data);
      } catch (error) {
        console.error("Falha ao buscar usuários:", error);
      }
    };
    fetchUsers();
  }, []);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    if (name === 'name') {
      const selectedUser = allUsers.find(user => user.nick === value || user.username === value);
      setCurrentParticipant({
        ...currentParticipant,
        name: value,
        habby_id: selectedUser ? selectedUser.habby_id : null
      });
    } else {
      setCurrentParticipant({ ...currentParticipant, [name]: value });
    }
  };

  // Lógica para Adicionar ou Atualizar um participante
  const handleAddOrUpdateParticipant = () => {
    if (currentParticipant.name && currentParticipant.fase) {
      if (editingIndex !== null) {
        // Lógica de atualização
        const updatedParticipants = [...participants];
        updatedParticipants[editingIndex] = currentParticipant;
        setParticipants(updatedParticipants);
        setEditingIndex(null); // Reseta o modo de edição
        alert("Participante atualizado com sucesso!");
      } else {
        // Lógica para adicionar novo participante
        setParticipants([...participants, currentParticipant]);
      }
      // Limpa o formulário
      setCurrentParticipant({ name: "", habby_id: null, fase: "", r1: "", r2: "", r3: "" });
    } else {
      alert("Por favor, preencha pelo menos o nome e a fase.");
    }
  };

  const removeParticipant = (index) => {
    if(window.confirm("Tem certeza que deseja remover este participante?")) {
        setParticipants(participants.filter((_, i) => i !== index));
    }
  };
  
  // --- NOVA FUNÇÃO PARA INICIAR A EDIÇÃO ---
  const handleEditParticipant = (index) => {
    setEditingIndex(index);
    // Carrega os dados do participante no formulário
    setCurrentParticipant(participants[index]);
  };

  // --- NOVA FUNÇÃO PARA CANCELAR A EDIÇÃO ---
  const cancelEdit = () => {
    setEditingIndex(null);
    // Limpa o formulário
    setCurrentParticipant({ name: "", habby_id: null, fase: "", r1: "", r2: "", r3: "" });
  };

  const finalizeSeason = async () => {
    if (participants.length === 0 || !startDate || !endDate) {
      alert("Adicione pelo menos um participante e defina as datas de início e fim.");
      return;
    }
    setLoading(true);
    try {
      const response = await axios.post("http://localhost:5000/seasons", {
        startDate,
        endDate,
        participants,
      });
      alert(response.data.message);
      setParticipants([]);
      setStartDate("");
      setEndDate("");
    } catch (error) {
      console.error("Erro ao finalizar temporada:", error);
      alert(`Erro ao finalizar temporada: ${error.response?.data?.error || error.message}`);
    } finally {
      setLoading(false);
    }
  };

  // --- NOVA FUNÇÃO PARA UPLOAD DE CSV ---
  const handleCsvUpload = (event) => {
    const file = event.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        const text = e.target.result;
        const lines = text.split('\n').slice(1); // Ignora o cabeçalho
        const newParticipants = lines.map(line => {
          const [name, habby_id, fase, r1, r2, r3] = line.split(',');
          // Validação básica para garantir que a linha não está vazia
          if (name && habby_id && fase) {
            return {
              name: name.trim(),
              habby_id: habby_id.trim(),
              fase: fase.trim(),
              r1: r1 ? r1.trim() : "0",
              r2: r2 ? r2.trim() : "0",
              r3: r3 ? r3.trim() : "0",
            };
          }
          return null;
        }).filter(p => p !== null); // Remove linhas nulas/inválidas
        setParticipants(prev => [...prev, ...newParticipants]);
        alert(`${newParticipants.length} participantes adicionados com sucesso do arquivo CSV!`);
      };
      reader.readAsText(file);
    }
    // Limpa o valor do input para permitir o upload do mesmo arquivo novamente
    event.target.value = null; 
  };
  // --- FIM DA NOVA FUNÇÃO ---

  if (loading) {
    return <div>Carregando...</div>;
  }

  return (
    <div className="register-page-wrapper">
      <div className="register-container">
        <h1>Registrar Pontuação de Membros</h1>

        {/* --- SEÇÃO DE UPLOAD DE CSV --- */}
        <div className="csv-upload-section">
          <h2>Importar por CSV</h2>
          <p>Anexe um arquivo .csv com as colunas: <b> name, habby_id, fase, r1, r2, r3</b></p>
          <label htmlFor="csv-upload" className="btn btn-primary btttn">
            <FaUpload /> Anexar Arquivo CSV
          </label>
          <input
            id="csv-upload"
            type="file"
            accept=".csv"
            style={{ display: 'none' }}
            onChange={handleCsvUpload}
          />
        </div>
        <hr/>
        {/* --- FIM DA SEÇÃO DE UPLOAD --- */}

        {/* O título muda dependendo se está editando ou adicionando */}
        <h2>{editingIndex !== null ? "Editando Participante" : "Registro Manual"}</h2>
        <div className="participant-form">
          <div className="form-row">
            {/* ... (campos do formulário permanecem os mesmos) ... */}
             <div className="form-group">
              <label>Nome do Membro</label>
              <input
                type="text"
                name="name"
                value={currentParticipant.name}
                onChange={handleInputChange}
                placeholder="Digite ou selecione um nome"
                list="user-suggestions"
              />
              <datalist id="user-suggestions">
                {allUsers.map(user => (
                  <option key={user.habby_id} value={user.nick || user.username} />
                ))}
              </datalist>
            </div>
            <div className="form-group">
              <label>Fase de Acesso</label>
              <input
                type="number"
                name="fase"
                value={currentParticipant.fase}
                onChange={handleInputChange}
              />
            </div>
          </div>
          <div className="form-row">
            <div className="form-group">
              <label>Rodada 1</label>
              <input
                type="number"
                name="r1"
                value={currentParticipant.r1}
                onChange={handleInputChange}
              />
            </div>
            <div className="form-group">
              <label>Rodada 2</label>
              <input
                type="number"
                name="r2"
                value={currentParticipant.r2}
                onChange={handleInputChange}
              />
            </div>
            <div className="form-group">
              <label>Rodada 3</label>
              <input
                type="number"
                name="r3"
                value={currentParticipant.r3}
                onChange={handleInputChange}
              />
            </div>
          </div>
          {/* Botão principal muda de acordo com o contexto (Adicionar ou Atualizar) */}
          <button className="btn-primary btn btttn" onClick={handleAddOrUpdateParticipant}>
            {editingIndex !== null ? <><FaEdit /> Atualizar Participante</> : <><FaPlus /> Adicionar à Lista</>}
          </button>
          {/* Botão para cancelar a edição (só aparece no modo de edição) */}
          {editingIndex !== null && (
            <button className="btn btn-secondary btttn" onClick={cancelEdit} style={{ marginLeft: '10px' }}>
              Cancelar
            </button>
          )}
        </div>

        <div className="participants-list">
          <h2>Lista para a Temporada</h2>
          {participants.length > 0 ? (
            <table>
              <thead>
                <tr>
                  <th>Nome</th>
                  <th>Acesso</th>
                  <th>1°Fase</th>
                  <th>2°Fase</th>
                  <th>3°Fase</th>
                  <th >Ação</th>
                </tr>
              </thead>
              <tbody>
                {participants.map((p, index) => (
                  <tr key={index}>
                    <td data-label="Nome">{p.name}</td>
                    <td data-label="Fase de Acesso"><span  className="leftlabel">{p.fase}</span></td>
                    <td data-label="1° Rodada">{p.r1}</td>
                    <td data-label="2° Rodada">{p.r2}</td>
                    <td data-label="3° Rodada">{p.r3}</td>
                    <td className="action-buttons">
                      <button className="btn btn-edit buttonEditDel" onClick={() => handleEditParticipant(index)}>
                        <FaEdit />
                      </button>
                      <button className="btn btn-delete buttonEditDel" onClick={() => removeParticipant(index)}>
                        <FaTrash />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p>Nenhum membro adicionado ainda.</p>
          )}
        </div>

        <div className="finalize-section">
          <h2>Finalizar Temporada</h2>
          <div className="form-row">
            <div className="form-group">
              <label>Data Inícial</label>
              <input
                className="form-input"
                type="date"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
              />
            </div>
            <div className="form-group">
              <label>Data Final</label>
              <input
                className="form-input"
                type="date"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
              />
            </div>
          </div>
          <button className="btn btn-primary btttn" onClick={finalizeSeason} disabled={participants.length === 0 || !startDate || !endDate}>
            {loading ? "Finalizando..." : "Finalizar e Salvar Ranking"}
          </button>
        </div>
      </div>
    </div>
  );
};

export default RegisterPage;